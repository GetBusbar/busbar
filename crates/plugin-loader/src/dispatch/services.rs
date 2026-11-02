// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::mem::size_of;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use busbar_contract::abi::host::service::{
    self as svc, check_bufs, check_disk_append_in, check_head, check_hook_call_in,
    check_random_fill_in, check_records_claim_in, check_work_record, may_pend, op, ClockNowIn,
    ClockReading, ContentScanIn, DestJudgeIn, DiskAppendIn, DiskWritten, EntitlementCheckIn,
    HookCallIn, HostSlots, RandomFillIn, RecordsClaimIn, RecordsGetIn, RecordsListIn,
    RecordsSecretIn, ServiceBufs, ServiceHead, ServiceOut, SessionEmitIn, SignIn, SnapshotReadIn,
    TicketMintIn, TicketTakeIn, TrustDecideIn, TrustDueIn, TrustServesIn, TrustSightIn,
    TrustSightItemIn, TrustStateIn, TrustVerifyIn, UnitNestIn, VerifyLookupIn, VerifyStoreIn,
    WorkFindIn, WorkOpenIn, WorkResumeIn, WorkSettleIn, SERVICES,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::check;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};

pub use busbar_contract::services::{
    Caller, DiskReport, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored,
};

use super::auth_handle::{
    AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, HeadCopy,
    RefusalBytes, RefuseAsk,
};
use super::ticket::{decode, InstanceWake, Waking};
use busbar_contract::abi::auth::FieldSpan;
use busbar_contract::abi::host::service::ItemSpan;
use busbar_contract::abi::mechanism::call::Span;

pub const NO_CALLER: &str = "no caller is bound to this instance";

pub const NO_TTL: &str = "a claim states its time to live";

pub const UNTICKETED: &str = "a service that may pend is callable only inside a ticketed op";

pub const NOT_THIS_CROSSING: &str =
    "a service handle names the ticket of the crossing that calls it";

pub const SHORT: &str = "the buffer is too small";

pub const FILL_OUT_OF_RANGE: &str = "a fill asks for 1 to MAX_RANDOM_FILL bytes";

pub const UNDECLARED_KIND: &str = "the caller does not declare that credential kind";

pub const NO_DESTINATION: &str = "the caller was granted no such destination";

pub const SNAPSHOT_NOT_READY: &str = "the snapshot is not ready";

pub const SECOND_SHORT: &str = "a second short answer on one handle";

pub const HANDLE_REBOUND: &str =
    "a handle is bound to the service and request it was first used for";

#[derive(Debug)]
enum Entry {
    Running {
        invocation: u64,
    },
    Done {
        invocation: u64,
        stored: Stored,
        shorts: u8,
        delivered: bool,
    },
}

impl Entry {
    fn invocation(&self) -> u64 {
        match self {
            Self::Running { invocation } | Self::Done { invocation, .. } => *invocation,
        }
    }
}

/// What a handle is bound to: the service's index and the fingerprint of the request it was first
/// used for ([`Fp`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bound {
    op: u32,
    req: u64,
}

/// A request's FINGERPRINT: each part, led by its length (so the parts' bounds are part of it),
/// folded eight bytes at a time, FNV-style with a rotate. No allocation; the parts are the
/// request's decoded arguments (never its buffers, which a short answer's re-call may change). It
/// tells one request from another a plugin sends on one handle; it is no defence against a plugin
/// that crafts a collision, which only ever misleads itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fp(u64);

impl Fp {
    pub(crate) const EMPTY: Self = Self(0xcbf2_9ce4_8422_2325);

    fn word(self, w: u64) -> Self {
        Self((self.0 ^ w).wrapping_mul(0x0100_0000_01b3).rotate_left(29))
    }

    #[must_use]
    pub(crate) fn with(self, part: &[u8]) -> Self {
        let mut f = self.word(part.len() as u64);
        let (words, rest) = part.as_chunks::<8>();
        for w in words {
            f = f.word(u64::from_le_bytes(*w));
        }
        if !rest.is_empty() {
            let mut b = [0u8; 8];
            b[..rest.len()].copy_from_slice(rest);
            f = f.word(u64::from_le_bytes(b));
        }
        f
    }

    pub(crate) fn of(parts: &[&[u8]]) -> u64 {
        parts.iter().fold(Self::EMPTY, |f, p| f.with(p)).0
    }
}

/// One ticket's results, stamped with the EPOCH of the op that issued them.
#[derive(Debug)]
struct Held {
    /// Minted fresh (never reused) when the ticket's first result of an op is stored; a forget
    /// (a new op or tick on the ticket, or its recycle) ends it.
    epoch: u64,
    entries: HashMap<Issue, (Bound, Entry)>,
    /// Inspection receipts share this epoch, but never a completion-handle namespace.
    inspections: HashMap<usize, inspection_store::Kept>,
    conditionals: HashMap<(usize, u64), conditional_store::Kept>,
    conditional_units: HashMap<usize, Result<Option<u64>, ()>>,
    retirement: HashMap<usize, (HostCtx, u64, [u8; 32])>,
}

impl Held {
    fn empty(&self) -> bool {
        self.entries.is_empty()
            && self.inspections.is_empty()
            && self.conditionals.is_empty()
            && self.conditional_units.is_empty()
            && self.retirement.is_empty()
    }
}

/// What one result is kept under on its ticket: the CALLER whose context issued the handle (THE
/// DESIGN §11.12 H2: "Every per-instance host registry keys by label"), and the handle's issue
/// number. Two instances whose ops share a ticket each count their handles from 0; neither ever
/// redeems, completes into or rebinds the other's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Issue {
    /// The caller's identity: the address of its leaked [`InstanceWake`] (`0`: no caller).
    caller: usize,
    seq: u32,
}

impl Issue {
    fn of(route: &Waking, seq: u32) -> Self {
        Self {
            caller: route
                .supplier
                .map_or(0, |w| std::ptr::from_ref::<InstanceWake>(w) as usize),
            seq,
        }
    }
}

/// The results of one dispatcher's services, by ticket then issue order, each ticket's under the
/// epoch of the op that issued them. A new op's handles count from 0 again, so a handle alone does
/// not name its op: a [`Completer`] carries its op's epoch, and a completion whose epoch is not the
/// ticket's current one is DROPPED, never stored under the next op's same-numbered handle and
/// never a wake for it (THE DESIGN §11.11 H2, §11.12).
/// Held in [`SHARDS`] maps by the worker a ticket's slot names, so calls on different workers'
/// tickets never wait on one another's lock.
#[derive(Debug, Default)]
pub struct ServiceStore {
    shards: [Mutex<HashMap<Ticket, Held>>; SHARDS],
    /// The last epoch minted.
    epochs: AtomicU64,
    /// The driver tickets' held exchanges, by handle (`super::held`).
    pub(crate) held: super::held::Held,
}

const SHARDS: usize = 16;

impl ServiceStore {
    fn shard(&self, worker: u32) -> std::sync::MutexGuard<'_, HashMap<Ticket, Held>> {
        self.shards[worker as usize % SHARDS]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn lock(&self, ticket: Ticket) -> std::sync::MutexGuard<'_, HashMap<Ticket, Held>> {
        self.shard(decode(ticket.slot).0)
    }

    fn complete(
        &self,
        h: CompletionHandle,
        issue: Issue,
        epoch: u64,
        invocation: u64,
        stored: Stored,
    ) -> bool {
        let mut map = self.lock(h.ticket);
        match map
            .get_mut(&h.ticket)
            .filter(|held| held.epoch == epoch)
            .and_then(|held| held.entries.get_mut(&issue))
        {
            Some((_, e)) => {
                if !matches!(&*e, Entry::Running { invocation: current } if *current == invocation)
                {
                    return false;
                }
                *e = Entry::Done {
                    invocation,
                    stored,
                    shorts: 0,
                    delivered: false,
                };
                true
            }
            _ => false,
        }
    }

    pub(crate) fn forget(&self, ticket: Ticket) -> usize {
        let retired = {
            let mut map = self.lock(ticket);
            let Some(h) = map.get_mut(&ticket) else {
                return 0;
            };
            let entries = std::mem::take(&mut h.entries);
            let inspections = std::mem::take(&mut h.inspections);
            h.conditional_units.clear();
            h.retirement.clear();
            let mut removed = Vec::new();
            let mut wakes = Vec::new();
            for (key, mut kept) in std::mem::take(&mut h.conditionals) {
                if kept.retire() {
                    if let Some(owner) = kept.completed_owner() {
                        wakes.push(owner);
                    }
                    h.conditionals.insert(key, kept);
                } else {
                    removed.push(kept);
                }
            }

            h.epoch = self.epochs.fetch_add(1, Ordering::Relaxed) + 1;
            let empty_owner = if h.empty() { map.remove(&ticket) } else { None };
            (entries, inspections, removed, wakes, empty_owner)
        };
        let count = retired.0.len();
        let (entries, inspections, removed, wakes, empty_owner) = retired;
        drop((entries, inspections, removed, empty_owner));
        for owner in wakes {
            super::conditional::wake_driver(owner);
        }
        count
    }

    pub(crate) fn forget_worker(&self, worker: u32) {
        let tickets: Vec<_> = self
            .shard(worker)
            .keys()
            .filter(|t| decode(t.slot).0 == worker)
            .copied()
            .collect();
        for ticket in tickets {
            self.forget(ticket);
        }
    }

    #[cfg(test)]
    pub(crate) fn keep(&self, ticket: Ticket, seq: u32) {
        let epoch = self.epochs.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock(ticket)
            .entry(ticket)
            .or_insert_with(|| Held {
                epoch,
                entries: HashMap::new(),
                inspections: HashMap::new(),
                conditionals: HashMap::new(),
                conditional_units: HashMap::new(),
                retirement: HashMap::new(),
            })
            .entries
            .insert(
                Issue { caller: 0, seq },
                (
                    Bound { op: 0, req: 0 },
                    Entry::Done {
                        invocation: epoch,
                        stored: Stored::ready(1),
                        shorts: 0,
                        delivered: true,
                    },
                ),
            );
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        (0..SHARDS as u32)
            .map(|w| {
                self.shard(w)
                    .values()
                    .map(|held| held.entries.len())
                    .sum::<usize>()
            })
            .sum()
    }
}

pub struct Completer {
    store: Weak<ServiceStore>,

    waking: Waking,
    handle: CompletionHandle,

    epoch: u64,
    invocation: u64,
}

impl std::fmt::Debug for Completer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completer")
            .field("handle", &self.handle)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Completer {
    pub fn complete(self, stored: Stored) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        let issue = Issue::of(&self.waking, self.handle.seq);
        if store.complete(self.handle, issue, self.epoch, self.invocation, stored) {
            self.waking.wake(self.handle.ticket);
        }
    }
}

/// THE HOST SERVICES A DISPATCHER SERVES, TAKEN LATE: a host may build its dispatcher before the
/// services it serves exist (busbar: before the configuration loads), so the dispatcher reads them
/// from this slot, which the host installs them into once they exist. Once: a second install is
/// refused and changes nothing, so a reload can never swap the services a running instance
/// reaches. Until then `pre` answers; with none, every service answers REFUSED. Read lock-free on
/// every call, which reaches the installed services themselves.
#[derive(Default)]
pub struct ServicesSlot {
    installed: std::sync::OnceLock<Arc<dyn HostServices>>,
    pre: Option<Arc<dyn HostServices>>,
}

impl ServicesSlot {
    #[must_use]
    pub fn late(pre: Arc<dyn HostServices>) -> Arc<Self> {
        Arc::new(Self {
            installed: std::sync::OnceLock::new(),
            pre: Some(pre),
        })
    }

    #[must_use]
    pub fn of(services: Arc<dyn HostServices>) -> Arc<Self> {
        Arc::new(Self {
            installed: std::sync::OnceLock::from(services),
            pre: None,
        })
    }

    pub fn install(&self, services: Arc<dyn HostServices>) -> bool {
        self.installed.set(services).is_ok()
    }

    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.installed.get().is_some()
    }

    #[must_use]
    pub fn get(&self) -> Option<&Arc<dyn HostServices>> {
        self.installed.get().or(self.pre.as_ref())
    }
}

/// What a dispatcher serves its instances from, borrowed from it for one call.
#[derive(Clone, Copy)]
pub(crate) struct Served<'a> {
    pub(crate) store: &'a Arc<ServiceStore>,
    pub(crate) provider: &'a dyn HostServices,
}

/// A service's answer, before it is written into the caller's `out` ([`write_out`]): the one
/// answer every slot table's frame writes (the host services, the connector's, the host I/O's).
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
    /// `ServiceOut::exited`: `1` only for `io.ends` on a program that has exited.
    pub exited: u8,
    /// The reason, for FAILED/REFUSED.
    pub error: &'static str,
}

impl Answered {
    pub(crate) const fn bare(outcome: Outcome, error: &'static str) -> Self {
        Self {
            outcome,
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            exited: 0,
            error,
        }
    }

    pub(crate) const fn fault() -> Self {
        Self::bare(Outcome::Fault, "")
    }

    pub(crate) const fn ready(value: u64, len: u64) -> Self {
        Self {
            value,
            len,
            ..Self::bare(Outcome::Ready, "")
        }
    }
}

/// Write `a` into the caller's `out` (none for a NULL `out`), as far as the caller stated it:
/// the `lent` bytes [`svc::lent_out`] read (an `out` grows by appending, so an older caller's
/// smaller one is never overrun); its outcome.
///
/// # Safety
/// A non-NULL `out` is the caller's, writable for the `lent` bytes it stated.
pub(crate) unsafe fn write_out(out: *mut ServiceOut, a: &Answered, lent: usize) -> RawOutcome {
    if !out.is_null() {
        let o = ServiceOut {
            size: size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(a.outcome),
            exited: a.exited,
            _reserved: [0; 2],
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
        // SAFETY: the caller's `out`, checked non-NULL, writable for the `lent` bytes it stated.
        unsafe { svc::write_out(out, o, lent) };
    }
    RawOutcome::of(a.outcome)
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
        exited: 0,
        error: stored.error,
    })
}

/// THE MECHANISM every service runs through, kind-neutral: `body` is the service itself, run at
/// most once per handle. `req` is the request's fingerprint ([`Fp`]): a ticketed handle is bound
/// to `head.op` and `req` at its first use, and a subsequent call on it naming another is FAULT and
/// quarantines the caller ([`HANDLE_REBOUND`]).
///
/// # Safety
/// As [`deliver`].
pub(crate) unsafe fn serve(
    store: &Arc<ServiceStore>,
    route: &Waking,
    head: &ServiceHead,
    req: u64,
    into: Option<&ServiceBufs>,
    body: impl FnOnce(Option<Completer>) -> Ran,
) -> Answered {
    serve_with(
        store,
        route,
        head,
        req,
        // SAFETY: the caller's contract, which is `deliver`'s.
        |stored| unsafe { deliver(stored, into) },
        body,
    )
}

pub(crate) fn serve_with(
    store: &Arc<ServiceStore>,
    route: &Waking,
    head: &ServiceHead,
    req: u64,
    put: impl FnOnce(&Stored) -> Result<Answered, Answered>,
    body: impl FnOnce(Option<Completer>) -> Ran,
) -> Answered {
    if head.handle.ticket.is_none() {
        if may_pend(head.op) {
            return Answered::bare(Outcome::Refused, UNTICKETED);
        }

        return match body(None) {
            Ran::Now(stored) => put(&stored).unwrap_or_else(|short| short),
            Ran::Later => Answered::fault(),
        };
    }
    let h = head.handle;

    if !crossing_names(h.ticket) {
        return Answered::bare(Outcome::Refused, NOT_THIS_CROSSING);
    }

    let caller = Issue::of(route, h.seq).caller;
    let domain = busbar_contract::abi::sdk::completion_retirement::Domain::Host;
    if !store.held.call(caller, domain, h) {
        return Answered::fault();
    }
    let bound = Bound { op: head.op, req };
    let a = serve_kept(store, route, h, bound, put, body);
    store
        .held
        .answered(caller, domain, h, a.outcome == Outcome::Pending);
    a
}

fn serve_kept(
    store: &Arc<ServiceStore>,
    route: &Waking,
    h: CompletionHandle,
    bound: Bound,
    put: impl FnOnce(&Stored) -> Result<Answered, Answered>,
    body: impl FnOnce(Option<Completer>) -> Ran,
) -> Answered {
    let issue = Issue::of(route, h.seq);
    let fresh = {
        let mut map = store.lock(h.ticket);
        let held = map.entry(h.ticket).or_insert_with(|| Held {
            epoch: store.epochs.fetch_add(1, Ordering::Relaxed) + 1,
            entries: HashMap::new(),
            inspections: HashMap::new(),
            conditionals: HashMap::new(),
            conditional_units: HashMap::new(),
            retirement: HashMap::new(),
        });
        let epoch = held.epoch;
        match held.entries.entry(issue) {
            std::collections::hash_map::Entry::Occupied(mut o) if o.get().0 == bound => {
                // SAFETY: the caller's contract.
                return unsafe { redeem(&mut o.get_mut().1, put) };
            }
            std::collections::hash_map::Entry::Occupied(_) => None,
            std::collections::hash_map::Entry::Vacant(v) => {
                let invocation = store.epochs.fetch_add(1, Ordering::Relaxed) + 1;
                v.insert((bound, Entry::Running { invocation }));
                Some((epoch, invocation))
            }
        }
    };
    let Some((epoch, invocation)) = fresh else {
        return rebound(route);
    };
    let completer = Completer {
        store: Arc::downgrade(store),
        waking: route.clone(),
        handle: h,
        epoch,
        invocation,
    };
    let ran = body(Some(completer));

    let mut map = store.lock(h.ticket);
    let Some((_, e)) = map
        .get_mut(&h.ticket)
        .filter(|held| held.epoch == epoch)
        .and_then(|held| held.entries.get_mut(&issue))
        .filter(|(_, entry)| entry.invocation() == invocation)
    else {
        return Answered::fault();
    };
    if let Ran::Now(stored) = ran {
        if matches!(e, Entry::Running { invocation: current } if *current == invocation) {
            *e = Entry::Done {
                invocation,
                stored,
                shorts: 0,
                delivered: false,
            };
        }
    }
    // SAFETY: the caller's contract.
    unsafe { redeem(e, put) }
}

/// A handle's stored result, written into the caller's buffers: PENDING while it runs; a short
/// answer counted, and a second one on the handle FAULT.
///
/// # Safety
/// As [`deliver`].
unsafe fn redeem(
    e: &mut Entry,
    put: impl FnOnce(&Stored) -> Result<Answered, Answered>,
) -> Answered {
    match e {
        Entry::Running { .. } => Answered::bare(Outcome::Pending, ""),
        Entry::Done {
            stored,
            shorts,
            delivered,
            ..
        } => {
            *delivered = false;
            if *shorts >= 2 {
                return Answered::bare(Outcome::Fault, SECOND_SHORT);
            }
            match put(stored) {
                Ok(a) => {
                    *delivered =
                        a.outcome != Outcome::Pending && a.needed_bytes == 0 && a.needed_items == 0;
                    a
                }
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
    }
}

fn rebound(route: &Waking) -> Answered {
    if let Some(wake) = route.supplier {
        super::plugin::quarantine(
            wake,
            "a plugin reused a service handle for another service or request; the instance is \
             quarantined",
        );
    }
    Answered::bare(Outcome::Fault, HANDLE_REBOUND)
}

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
    snapshot_read: Some(snapshot_read),
    trust_sight_item: Some(trust_sight_item),
    trust_serves: Some(trust_serves),
    trust_decide: Some(trust_decide),
    trust_state: Some(trust_state),
    session_emit: Some(session_emit),
    auth_call: Some(auth_call),
    unit_hand_in: Some(unit_hand_in),
    unit_refuse: Some(unit_refuse),
    ticket_mint: Some(ticket_mint),
    ticket_take: Some(ticket_take),
};

pub(crate) fn new_op(wake: &'static super::ticket::InstanceWake, ticket: Ticket) {
    let Some(route) = Waking::of(wake).and_then(|w| w.route.upgrade()) else {
        return;
    };
    if let Some(served) = route.services() {
        served.store.forget(ticket);
    }
}

fn bytes_of(s: AbiStr, field: &'static str) -> Option<Vec<u8>> {
    check::text(s, field).ok()?;
    // SAFETY: a range of the caller's, live for the call, its length capped by `lent_str` before
    // the slice is formed; copied before any pend.
    unsafe { super::validate::lent_str(s) }.map(<[u8]>::to_vec)
}

fn blob_of(b: Blob, field: &'static str) -> Option<Vec<u8>> {
    check::listed(b.ptr, b.len, field).ok()?;
    // SAFETY: as `bytes_of`.
    unsafe { super::validate::lent(b.ptr, b.len) }.map(<[u8]>::to_vec)
}

fn text_of(s: AbiStr, field: &'static str) -> Option<String> {
    String::from_utf8(bytes_of(s, field)?).ok()
}

fn later_of(completer: Option<Completer>) -> Option<Later> {
    completer.map(|c| -> Later { Box::new(move |s| c.complete(s)) })
}

fn slot(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(Served<'_>, Waking, ServiceHead) -> Answered,
) -> RawOutcome {
    framed(input, out, service, in_size, |head| {
        let unbound = || Answered::bare(Outcome::Refused, "no host services are bound");
        let Some(waking) = super::handle::resolve(ctx).and_then(Waking::of) else {
            return unbound();
        };
        let Some(route) = waking.route.upgrade() else {
            return unbound();
        };
        match route.services() {
            Some(served) => body(served, waking, head),
            None => unbound(),
        }
    })
}

fn framed(
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(ServiceHead) -> Answered,
) -> RawOutcome {
    let lent = if out.is_null() {
        0
    } else {
        // SAFETY: the caller's non-NULL `out`, its leading `size` readable.
        match unsafe { svc::lent_out(out) } {
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
        if check_head(&head, service, in_size).is_err() {
            return Answered::fault();
        }
        if may_pend(service) && head.handle.ticket.is_none() {
            return Answered::bare(Outcome::Refused, UNTICKETED);
        }
        if !head.handle.ticket.is_none() && !crossing_names(head.handle.ticket) {
            return Answered::bare(Outcome::Refused, NOT_THIS_CROSSING);
        }
        body(head)
    }))
    .unwrap_or_else(|_| Answered::fault());
    // SAFETY: the caller's `out`, as the call shape lends it, writable for the `lent` bytes it
    // stated.
    unsafe { write_out(out, &a, lent) }
}

/// ONE HOST-SERVICE THUNK (THE DESIGN §11.12): the `extern "C"` fn of a slot, over the frame
/// `$frame` (this module's `slot` or `scoped`, or the connector table's `slot`) with the closure
/// parameters the frame passes, then `i`: the service's `In`, read whole once the head has covered
/// it. `body` is the service.
#[rustfmt::skip]
macro_rules! service {
    ($name:ident, $frame:ident, $op:expr, $in:ty, |$a:pat_param, $b:pat_param, $c:pat_param, $i:ident| $body:block) => {
        extern "C" fn $name(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
            $frame(ctx, input, out, $op, size_of::<$in>(), |$a, $b, $c| {
                // SAFETY: the head covered the service's `In`.
                let $i = unsafe { input.cast::<$in>().read_unaligned() };
                $body
            })
        }
    };
    ($name:ident, $frame:ident, $op:expr, $in:ty, |$a:pat_param, $b:pat_param, $c:pat_param, $d:pat_param, $i:ident| $body:block) => {
        extern "C" fn $name(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
            $frame(ctx, input, out, $op, size_of::<$in>(), |$a, $b, $c, $d| {
                // SAFETY: the head covered the service's `In`.
                let $i = unsafe { input.cast::<$in>().read_unaligned() };
                $body
            })
        }
    };
}
pub(super) use service;

service! {
    clock_now, slot, op::CLOCK_NOW, ClockNowIn, |served, _, _, i| {
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
    }
}

service! {
    dest_judge, slot, op::DEST_JUDGE, DestJudgeIn, |served, route, head, i| {
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
        // SAFETY: a checked range of the caller's, live for the call, its length capped before
        // the slice is formed; copied before any pend.
        let Some(dest) = (unsafe { super::validate::lent_str(i.dest) }) else {
            return Answered::fault();
        };
        let dest = String::from_utf8_lossy(dest).into_owned();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers, where the judged addresses go.
        unsafe {
            let req = Fp::of(&[
                dest.as_bytes(),
                &i.egress_class.to_le_bytes(),
                &i.flags.to_le_bytes(),
            ]);
            serve(
                served.store,
                &route,
                &head,
                req,
                Some(&i.into),
                |completer| {
                    let later = completer.map(|c| -> Later { Box::new(move |s| c.complete(s)) });
                    provider.dest_judge(&dest, i.egress_class, i.flags, later)
                },
            )
        }
    }
}

fn scoped(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(Served<'_>, Waking, ServiceHead, &Caller) -> Answered,
) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service,
        in_size,
        |served, route, head| match route.supplier.and_then(|w| w.caller.get()) {
            Some(c) => body(served, route, head, c),
            None => Answered::bare(Outcome::Refused, NO_CALLER),
        },
    )
}

/// Run a may-pend service under the mechanism: `run` gets the completer's [`Later`], which a
/// ticketed call always has. `req` is the request's fingerprint, as [`serve`]'s.
///
/// # Safety
/// As [`deliver`].
unsafe fn pended(
    served: &Served<'_>,
    route: &Waking,
    head: &ServiceHead,
    req: u64,
    into: Option<&ServiceBufs>,
    run: impl FnOnce(Later) -> Ran,
) -> Answered {
    // SAFETY: the caller's contract.
    unsafe {
        serve(
            served.store,
            route,
            head,
            req,
            into,
            |completer| match later_of(completer) {
                Some(later) => run(later),
                None => Ran::Now(Stored::refused(UNTICKETED)),
            },
        )
    }
}

service! {
    records_get, scoped, op::RECORDS_GET, RecordsGetIn, |served, route, head, caller, i| {
        let (Some(kind), Some(key)) = (
            text_of(i.kind, "records_get.kind"),
            bytes_of(i.key, "records_get.key"),
        ) else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[kind.as_bytes(), &key]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.records_get(caller, &kind, &key, later)
            })
        }
    }
}

fn credential_kinds(route: &Waking) -> &'static [String] {
    let Some(wake) = route.supplier else {
        return &[];
    };
    wake.credential_kinds.get().map_or(&[], Vec::as_slice)
}

service! {
    records_secret, slot, op::RECORDS_SECRET, RecordsSecretIn, |served, route, head, i| {
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
        if !credential_kinds(&route).contains(&kind) {
            return Answered::bare(Outcome::Refused, UNDECLARED_KIND);
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[kind.as_bytes(), id.as_bytes()]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.records_secret(&kind, &id, later)
            })
        }
    }
}

fn destination(route: &Waking, key: &str) -> Option<busbar_contract::services::DiskDest> {
    let wake = route.supplier?;
    if !wake.destinations.get()?.iter().any(|k| k == key) {
        return None;
    }
    if let Some(binding) = super::export_bindings::current() {
        return binding.destinations.iter().find(|d| d.key == key).cloned();
    }
    let bound = wake
        .bound
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    bound.iter().find(|d| d.key == key).cloned()
}

service! {
    disk_append, slot, op::DISK_APPEND, DiskAppendIn, |served, route, head, i| {
        if check_disk_append_in(&i).is_err() {
            return Answered::fault();
        }
        let Some(bytes) = blob_of(i.bytes, "disk_append.bytes") else {
            return Answered::fault();
        };
        // Own the copy before parsing another field: malformed keys, replay and refusal also
        // retire initialized request bytes without issuing a disk job.
        let mut bytes = zeroize::Zeroizing::new(bytes);
        let Some(key) = text_of(i.dest_key, "disk_append.dest_key") else {
            return Answered::fault();
        };
        let Some(dest) = destination(&route, &key) else {
            // SAFETY: the caller's result slot, checked non-NULL by `check_disk_append_in`.
            unsafe {
                i.result.write_unaligned(DiskWritten {
                    size: size_of::<DiskWritten>() as u32,
                    rotated: 0,
                    faults: 0,
                    _reserved: [0; 2],
                    written: 0,
                });
            }
            let mut a = Answered::bare(Outcome::Failed, NO_DESTINATION);
            a.value = svc::DISK_OPEN_FAILED;
            return a;
        };
        let whole = bytes.len() as u64;
        let req = Fp::of(&[key.as_bytes(), &bytes]);
        let provider = served.provider;
        // SAFETY: no buffer: the result is the `DiskWritten` slot, written below.
        let mut a = unsafe {
            pended(&served, &route, &head, req, None, |later| {
                provider.disk_append(&dest, std::mem::take(&mut *bytes), later)
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
    }
}

service! {
    records_list, scoped, op::RECORDS_LIST, RecordsListIn, |served, route, head, caller, i| {
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
        let req = Fp::of(&[
            kind.as_bytes(),
            &prefix,
            &[u8::from(!i.after.ptr.is_null())],
            &after,
            &i.limit.to_le_bytes(),
        ]);
        let list = RecordsList {
            kind,
            prefix,
            after: (!i.after.ptr.is_null()).then_some(after),
            limit: i.limit,
        };
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.records_list(caller, list, later)
            })
        }
    }
}

service! {
    records_claim, scoped, op::RECORDS_CLAIM, RecordsClaimIn, |served, route, head, caller, i| {
        let (Some(kind), Some(key)) = (
            text_of(i.kind, "records_claim.kind"),
            bytes_of(i.key, "records_claim.key"),
        ) else {
            return Answered::fault();
        };
        if check_records_claim_in(&i).is_err() {
            return Answered::bare(Outcome::Refused, NO_TTL);
        }
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[kind.as_bytes(), &key, &i.ttl_ms.to_le_bytes()]);
            pended(&served, &route, &head, req, None, |later| {
                provider.records_claim(caller, &kind, &key, i.ttl_ms, later)
            })
        }
    }
}

service! {
    sign, scoped, op::SIGN, SignIn, |served, route, head, caller, i| {
        let Some(data) = blob_of(i.data, "sign.data") else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            serve(
                served.store,
                &route,
                &head,
                Fp::of(&[&data]),
                Some(&i.into),
                |_| Ran::Now(provider.sign(caller, &data)),
            )
        }
    }
}

service! {
    trust_sight, scoped, op::TRUST_SIGHT, TrustSightIn, |served, route, head, caller, i| {
        let Some(counterparty) = text_of(i.counterparty, "trust_sight.counterparty") else {
            return Answered::fault();
        };
        let provider = served.provider;
        match i.outcome {
            svc::TRUST_REACHED => {}
            // Unreached: the last verdict, nothing sighted (the hash is unread).
            svc::TRUST_UNREACHABLE => {
                // SAFETY: no buffer is named.
                return unsafe {
                    let req = Fp::of(&[&i.outcome.to_le_bytes(), counterparty.as_bytes()]);
                    pended(&served, &route, &head, req, None, |_| {
                        Ran::Now(provider.trust_unreached(caller, &counterparty))
                    })
                };
            }
            _ => return Answered::fault(),
        }
        let Some(hash) = text_of(i.catalogue_hash, "trust_sight.catalogue_hash") else {
            return Answered::fault();
        };
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[
                &i.outcome.to_le_bytes(),
                counterparty.as_bytes(),
                hash.as_bytes(),
            ]);
            pended(&served, &route, &head, req, None, |later| {
                provider.trust_sight(caller, &counterparty, &hash, later)
            })
        }
    }
}

service! {
    trust_sight_item, scoped, op::TRUST_SIGHT_ITEM, TrustSightItemIn, |served, route, head, caller, i| {
        let (Some(counterparty), Some(item), Some(digest)) = (
            text_of(i.counterparty, "trust_sight_item.counterparty"),
            text_of(i.item, "trust_sight_item.item"),
            text_of(i.digest, "trust_sight_item.digest"),
        ) else {
            return Answered::fault();
        };
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[counterparty.as_bytes(), item.as_bytes(), digest.as_bytes()]);
            serve(served.store, &route, &head, req, None, |_| {
                Ran::Now(provider.trust_sight_item(caller, &counterparty, &item, &digest))
            })
        }
    }
}

service! {
    trust_serves, scoped, op::TRUST_SERVES, TrustServesIn, |served, route, head, caller, i| {
        let (Some(counterparty), Some(item), Some(digest)) = (
            text_of(i.counterparty, "trust_serves.counterparty"),
            text_of(i.item, "trust_serves.item"),
            text_of(i.digest, "trust_serves.digest"),
        ) else {
            return Answered::fault();
        };
        let req = Fp::of(&[counterparty.as_bytes(), item.as_bytes(), digest.as_bytes()]);
        let some = |s: String| (!s.is_empty()).then_some(s);
        let (item, digest) = (some(item), some(digest));
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            serve(served.store, &route, &head, req, None, |_| {
                Ran::Now(provider.trust_serves(
                    caller,
                    &counterparty,
                    item.as_deref(),
                    digest.as_deref(),
                ))
            })
        }
    }
}

service! {
    trust_decide, scoped, op::TRUST_DECIDE, TrustDecideIn, |served, route, head, caller, i| {
        let approve = match i.decision {
            svc::TRUST_DECIDE_APPROVE => true,
            svc::TRUST_DECIDE_REVOKE => false,
            _ => return Answered::fault(),
        };
        let (Some(counterparty), Some(item), Some(expected)) = (
            text_of(i.counterparty, "trust_decide.counterparty"),
            text_of(i.item, "trust_decide.item"),
            text_of(i.expected, "trust_decide.expected"),
        ) else {
            return Answered::fault();
        };
        let req = Fp::of(&[
            &[u8::from(approve)],
            counterparty.as_bytes(),
            item.as_bytes(),
            expected.as_bytes(),
        ]);
        let some = |s: String| (!s.is_empty()).then_some(s);
        let (item, expected) = (some(item), some(expected));
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            serve(served.store, &route, &head, req, None, |_| {
                let key = busbar_contract::services::TrustKeyRef {
                    counterparty: &counterparty,
                    item: item.as_deref(),
                };
                Ran::Now(provider.trust_decide(caller, key, expected.as_deref(), approve))
            })
        }
    }
}

service! {
    trust_state, scoped, op::TRUST_STATE, TrustStateIn, |served, route, head, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let Some(counterparty) = text_of(i.counterparty, "trust_state.counterparty") else {
            return Answered::fault();
        };
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[counterparty.as_bytes()]);
            serve(served.store, &route, &head, req, Some(&i.into), |_| {
                Ran::Now(provider.trust_state(caller, &counterparty))
            })
        }
    }
}

service! {
    trust_due, scoped, op::TRUST_DUE, TrustDueIn, |served, route, head, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            serve(
                served.store,
                &route,
                &head,
                Fp::of(&[]),
                Some(&i.into),
                |_| Ran::Now(provider.trust_due(caller)),
            )
        }
    }
}

service! {
    trust_verify, scoped, op::TRUST_VERIFY, TrustVerifyIn, |served, route, head, caller, i| {
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
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[counterparty.as_bytes(), &payload, &signatures]);
            serve(served.store, &route, &head, req, Some(&i.into), |_| {
                Ran::Now(provider.trust_verify(caller, &counterparty, &payload, &signatures))
            })
        }
    }
}

thread_local! {
    /// The unit the crossing on this thread serves.
    static SERVING: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// The ticket the crossing on this thread carries (`Ticket::NONE` for a ticket-less one);
    /// `None` outside any crossing.
    static CROSSING: std::cell::Cell<Option<Ticket>> = const { std::cell::Cell::new(None) };
}

pub(crate) struct Crossing(Option<Ticket>);

impl Drop for Crossing {
    fn drop(&mut self) {
        CROSSING.with(|c| c.set(self.0));
    }
}

pub(crate) fn crossing(ticket: Ticket) -> Crossing {
    Crossing(CROSSING.with(|c| c.replace(Some(ticket))))
}

fn crossing_names(ticket: Ticket) -> bool {
    CROSSING
        .with(std::cell::Cell::get)
        .is_none_or(|t| t == ticket)
}

pub(crate) struct Serving(Option<u64>);

impl Drop for Serving {
    fn drop(&mut self) {
        SERVING.with(|s| s.set(self.0));
    }
}

pub(crate) fn serving(unit: Option<u64>) -> Serving {
    Serving(SERVING.with(|s| s.replace(unit)))
}

pub(crate) fn serving_unit() -> Option<u64> {
    SERVING.with(std::cell::Cell::get)
}

thread_local! {
    /// The deadline (the loader's clock, nanoseconds) of the op whose crossing is on this thread.
    static OP_DEADLINE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) struct OpDeadline(Option<u64>);

impl Drop for OpDeadline {
    fn drop(&mut self) {
        OP_DEADLINE.with(|d| d.set(self.0));
    }
}

pub(crate) fn op_deadline(head: &busbar_contract::abi::mechanism::call::InHead) -> OpDeadline {
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    let deadline = (head.deadline_ns != 0
        && DeadlineClass::from_raw(head.deadline_class) != Some(DeadlineClass::WriteBehind))
    .then_some(head.deadline_ns);
    OpDeadline(OP_DEADLINE.with(|d| d.replace(deadline)))
}

fn op_remaining() -> Option<std::time::Duration> {
    OP_DEADLINE
        .with(std::cell::Cell::get)
        .map(|d| std::time::Duration::from_nanos(d.saturating_sub(super::now_ns())))
}

service! {
    entitlement_check, scoped, op::ENTITLEMENT_CHECK, EntitlementCheckIn, |served, route, head, caller, i| {
        let Some(target) = text_of(i.target, "entitlement_check.target") else {
            return Answered::fault();
        };
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[target.as_bytes()]);
            serve(served.store, &route, &head, req, None, |_| {
                Ran::Now(provider.entitlement_check(caller, unit, &target))
            })
        }
    }
}

service! {
    session_emit, scoped, op::SESSION_EMIT, SessionEmitIn, |served, route, head, caller, i| {
        let Some(bytes) = blob_of(i.bytes, "session_emit.bytes") else {
            return Answered::fault();
        };
        if svc::check_session_emit_in(&i).is_err() {
            return Answered::bare(Outcome::Refused, EMIT_NOTHING);
        }
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[&i.session.to_le_bytes(), &bytes]);
            serve(served.store, &route, &head, req, None, |_| {
                Ran::Now(provider.session_emit(caller, i.session, &bytes))
            })
        }
    }
}

pub const NOT_EXACT: &str = "the `in` is not exactly its service's size";

pub const UNIT_UNVERIFIED: &str = "the host holds no unit to verify this one against";

pub const AUTH_IN_MALFORMED: &str = "the auth-handle `in` breaks its check";

pub const PEER_ANSWER_NAMES: &str =
    "a peer-point answer is continue or stop, with nothing beside it";

pub const AUTH_HANDLE_NOT_SERVED: &str = "the auth handle is not yet served";

fn exact<T: Copy>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    body: impl FnOnce(T, u64, Arc<ServiceStore>, Waking, ServiceHead) -> Answered,
) -> RawOutcome {
    framed(input, out, service, size_of::<ServiceHead>(), |head| {
        let route = super::handle::resolve(ctx).and_then(Waking::of);
        let Some((store, route)) =
            route.and_then(|r| Some((r.route.upgrade()?.service_store()?, r)))
        else {
            return Answered::bare(Outcome::Refused, "no host services are bound");
        };
        if svc::check_head_exact(&head, service, size_of::<T>()).is_err() {
            return Answered::bare(Outcome::Refused, NOT_EXACT);
        }
        // SAFETY: the caller's non-NULL `in`, stating exactly a `T`.
        let i = unsafe { input.cast::<T>().read_unaligned() };
        body(i, super::handle::instance_id(ctx).0, store, route, head)
    })
}

fn auth_host(route: &Waking) -> Option<Arc<dyn AuthHandleHost>> {
    route.route.upgrade()?.auth_handle()
}

fn refused_ref(owner: u64, generation: u64, r: &svc::AuthRef) -> Option<Answered> {
    super::auth_handle::verify_auth_ref(owner, generation, r)
        .err()
        .map(|e| Answered::bare(Outcome::Refused, e.text()))
}

fn request_generation(
    owner: u64,
    host: Option<&Arc<dyn AuthHandleHost>>,
    unit: &svc::UnitRef,
    conn: u64,
    stream: u64,
    peer: bool,
    teardown: bool,
) -> Result<u64, &'static str> {
    let context = super::framing_context::current();
    if let Some(context) = &context {
        context.check(owner, conn, teardown)?;
    } else if host.is_some_and(|host| host.requires_scope()) {
        return Err(super::framing_context::CONTEXT_REFUSED);
    }
    if !unit.is_none() {
        if let Some(secret) = host.and_then(|h| h.unit_secret(owner, unit.id)) {
            return Ok(secret.generation);
        }
    }
    if let Some(context) = context.filter(|scope| scope.listener() != 0) {
        if let Some(generation) = context.policy_generation(stream, peer) {
            return Ok(generation);
        }
        if host.is_some_and(|host| host.requires_scope()) {
            return Err(super::framing_context::CONTEXT_REFUSED);
        }
    }
    Ok(super::auth_handle::generation())
}

fn refused_unit(
    owner: u64,
    host: Option<&Arc<dyn AuthHandleHost>>,
    u: &svc::UnitRef,
) -> Option<Answered> {
    if u.is_none() {
        return None;
    }
    let Some(host) = host else {
        return Some(Answered::bare(Outcome::Refused, UNIT_UNVERIFIED));
    };
    let refused = match host.unit_secret(owner, u.id) {
        Some(s) => super::auth_handle::verify_unit_ref(s.secret, s.generation, owner, s.line, u)
            .err()
            .map(super::auth_handle::RefRefused::text),
        None => Some(super::auth_handle::REF_NOT_MINTED),
    };
    refused.map(|e| Answered::bare(Outcome::Refused, e))
}

fn lent_text(s: AbiStr) -> Option<String> {
    // SAFETY: a range of the caller's, live for the call, its length capped before the slice is
    // formed; copied before any pend.
    let bytes = unsafe { super::validate::lent_str(s) }?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn head_copy(v: &svc::HeadView) -> Option<HeadCopy> {
    let fields = if v.fields_len == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's field list, checked non-NULL with its count by `check_head_view`
        // and at most `MAX_SPANS` long; copied before any pend.
        let lent = unsafe { std::slice::from_raw_parts(v.fields, v.fields_len) };
        lent.iter()
            .map(|f| {
                // SAFETY: a range of the caller's, as `lent_text`.
                let value = unsafe { super::validate::lent_str(f.value) }?.to_vec();
                Some((lent_text(f.name)?, value))
            })
            .collect::<Option<Vec<_>>>()?
    };
    Some(HeadCopy {
        method: lent_text(v.method)?,
        target: lent_text(v.target)?,
        authority: lent_text(v.authority)?,
        query: (v.query.len != 0 || !v.query.ptr.is_null())
            .then(|| lent_text(v.query))
            .flatten(),
        fields,
    })
}

const UNIT_PREFIX: usize = 16;

fn stored_auth(r: Result<AuthCallAnswer, &'static str>) -> Stored {
    let a = match r {
        Ok(a) => a,
        Err(e) => return Stored::refused(e),
    };
    let mut stored = Stored::ready(u64::from(a.flow));
    stored.bytes.extend_from_slice(&a.unit.id.to_le_bytes());
    stored.bytes.extend_from_slice(&a.unit.mac.to_le_bytes());
    for (name, flags) in a.strips {
        let at = stored.bytes.len() as u32;
        stored.bytes.extend_from_slice(name.as_bytes());
        stored.spans.push(ItemSpan {
            key: Span {
                offset: at,
                len: name.len() as u32,
            },
            value: Span {
                offset: check::SPAN_ABSENT,
                len: flags,
            },
        });
    }
    stored
}

/// Write a stored `auth.call` answer ([`stored_auth`]) into the caller's `buf`, `spans` and answer
/// slot; `Err` is the short answer, nothing written (the short-buffer rule). Any other outcome is
/// answered as stored, the slot untouched.
///
/// # Safety
/// `i`'s buffers are the caller's, live and writable for their capacities (checked by
/// [`svc::check_auth_call_in`]) and its answer slot is non-NULL.
unsafe fn put_auth(stored: &Stored, i: &svc::AuthCallIn) -> Result<Answered, Answered> {
    if stored.outcome != Outcome::Ready {
        return Ok(Answered::bare(stored.outcome, stored.error));
    }
    let (unit, names) = stored.bytes.split_at(UNIT_PREFIX.min(stored.bytes.len()));

    if i.point == busbar_contract::abi::auth::POINT_PEER
        && (!names.is_empty() || !stored.spans.is_empty() || unit.iter().any(|b| *b != 0))
    {
        return Ok(Answered::bare(Outcome::Refused, PEER_ANSWER_NAMES));
    }
    let word = |at: usize| {
        unit.get(at..at + 8)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_le_bytes)
    };
    if names.len() > i.cap || stored.spans.len() > i.spans_cap {
        return Err(Answered {
            needed_bytes: names.len() as u64,
            needed_items: stored.spans.len() as u64,
            ..Answered::bare(Outcome::Failed, SHORT)
        });
    }
    // SAFETY: both fit their capacities, checked above; the buffers and the slot are the caller's.
    unsafe {
        if !names.is_empty() {
            std::ptr::copy_nonoverlapping(names.as_ptr(), i.buf, names.len());
        }
        for (n, s) in stored.spans.iter().enumerate() {
            i.spans.add(n).write_unaligned(FieldSpan {
                name: Span {
                    offset: s.key.offset - UNIT_PREFIX as u32,
                    len: s.key.len,
                },
                value: Span {
                    offset: check::SPAN_ABSENT,
                    len: 0,
                },
                flags: s.value.len,
                _reserved: 0,
            });
        }
        i.answer.write_unaligned(svc::AuthAnswer {
            size: size_of::<svc::AuthAnswer>() as u32,
            flow: stored.value as u32,
            unit: svc::UnitRef {
                id: word(0),
                mac: word(8),
            },
        });
    }
    Ok(Answered {
        len: names.len() as u64,
        items: stored.spans.len() as u64,
        ..Answered::bare(Outcome::Ready, "")
    })
}

fn service_framing(
    owner: u64,
    conn: u64,
    ticket: Ticket,
    teardown: bool,
) -> Result<Option<u64>, &'static str> {
    match super::framing_context::current() {
        Some(context) => {
            context.check(owner, conn, teardown)?;
            Ok(Some(context.leg()))
        }
        None => Ok((!ticket.is_none()).then(|| super::auth_handle::framing_of(ticket))),
    }
}

fn claim_stream_operation(
    ticket: Ticket,
    stream: u64,
    generation: u64,
    required: bool,
) -> Result<(), &'static str> {
    if let Some(context) = super::framing_context::current() {
        if required || context.policy_generation(stream, false).is_some() {
            context.claim_stream_operation(ticket, stream, generation)?;
        }
    }
    Ok(())
}

extern "C" fn auth_call(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    exact::<svc::AuthCallIn>(
        ctx,
        input,
        out,
        op::AUTH_CALL,
        |i, owner, store, route, head| {
            let host = auth_host(&route);
            let generation = match request_generation(
                owner,
                host.as_ref(),
                &i.unit,
                i.conn,
                i.stream,
                i.point == busbar_contract::abi::auth::POINT_PEER,
                false,
            ) {
                Ok(generation) => generation,
                Err(error) => return Answered::bare(Outcome::Refused, error),
            };
            if let Some(r) = refused_ref(owner, generation, &i.auth)
                .or_else(|| refused_unit(owner, host.as_ref(), &i.unit))
            {
                return r;
            }
            match svc::check_auth_call_in(&i) {
                Err(f) if f.field == "head_view.scheme" && f.rule == check::Rule::Missing => {
                    return Answered::bare(Outcome::Refused, svc::SCHEME_UNDECLARED_REFUSED);
                }
                Err(_) => return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED),
                Ok(()) => {}
            }
            let Some(host) = host else {
                return Answered::bare(Outcome::Refused, AUTH_HANDLE_NOT_SERVED);
            };

            let Some(request) = head_copy(&i.request) else {
                return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED);
            };
            let body = if i.point == busbar_contract::abi::auth::POINT_HEAD_BODY {
                match blob_of(i.body, "auth_call.body") {
                    Some(b) => Some(b),
                    None => return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED),
                }
            } else {
                None
            };
            let framing = match service_framing(owner, i.conn, head.handle.ticket, false) {
                Ok(Some(f)) => f,
                Ok(None) => return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED),
                Err(e) => return Answered::bare(Outcome::Refused, e),
            };
            if i.point != busbar_contract::abi::auth::POINT_PEER {
                if let Err(error) = claim_stream_operation(
                    head.handle.ticket,
                    i.stream,
                    generation,
                    host.requires_scope(),
                ) {
                    return Answered::bare(Outcome::Refused, error);
                }
            }
            let ask = AuthCallAsk {
                owner,
                generation,
                auth: i.auth.id,
                unit: i.unit,
                point: i.point,
                conn: i.conn,
                stream: i.stream,
                request,
                body,
                deadline: op_remaining(),
                framing,
            };

            let req = Fp::of(&[
                &i.auth.id.to_le_bytes(),
                &i.unit.id.to_le_bytes(),
                &i.point.to_le_bytes(),
                &i.conn.to_le_bytes(),
                &i.stream.to_le_bytes(),
            ]);
            serve_with(
                &store,
                &route,
                &head,
                req,
                // SAFETY: `i`'s buffers and slot checked by `check_auth_call_in` above.
                |stored| unsafe { put_auth(stored, &i) },
                |completer| {
                    let Some(c) = completer else {
                        return Ran::Now(Stored::refused(UNTICKETED));
                    };
                    let done: AuthDone = Box::new(move |r| c.complete(stored_auth(r)));
                    match host.auth_call(ask, done) {
                        AuthRan::Now(r) => Ran::Now(stored_auth(r)),
                        AuthRan::Pending => Ran::Later,
                    }
                },
            )
        },
    )
}

extern "C" fn unit_hand_in(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    exact::<svc::UnitHandInIn>(
        ctx,
        input,
        out,
        op::UNIT_HAND_IN,
        |i, owner, _, route, head| {
            let host = auth_host(&route);
            let generation = match request_generation(
                owner,
                host.as_ref(),
                &i.unit,
                i.conn,
                i.stream,
                false,
                false,
            ) {
                Ok(generation) => generation,
                Err(error) => return Answered::bare(Outcome::Refused, error),
            };
            if let Some(r) = refused_ref(owner, generation, &i.auth)
                .or_else(|| refused_unit(owner, host.as_ref(), &i.unit))
            {
                return r;
            }
            if svc::check_unit_hand_in_in(&i).is_err() {
                return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED);
            }

            if i.request.scheme == svc::SCHEME_UNDECLARED {
                return Answered::bare(Outcome::Refused, svc::SCHEME_UNDECLARED_REFUSED);
            }
            let framing = match service_framing(owner, i.conn, head.handle.ticket, false) {
                Ok(f) => f,
                Err(e) => return Answered::bare(Outcome::Refused, e),
            };
            if super::auth_handle::is_none_line(owner, i.auth.id) {
                let Some(unit) = super::auth_handle::mint_none_unit(owner, i.line) else {
                    return Answered::bare(Outcome::Failed, super::auth_handle::REF_NO_KEY);
                };
                // SAFETY: the checked caller-owned answer slot is live for this call.
                unsafe {
                    i.answer.write_unaligned(svc::AuthAnswer {
                        size: size_of::<svc::AuthAnswer>() as u32,
                        flow: svc::FLOW_CONTINUE,
                        unit,
                    });
                }
                return Answered::ready(0, 0);
            }
            let Some(host) = host else {
                return Answered::bare(Outcome::Refused, AUTH_HANDLE_NOT_SERVED);
            };
            let Some(request) = head_copy(&i.request) else {
                return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED);
            };
            let ask = HandInAsk {
                owner,
                generation,
                auth: i.auth.id,
                unit: i.unit,
                line: i.line,
                conn: i.conn,
                stream: i.stream,
                request,
                framing,
            };
            if let Err(error) = claim_stream_operation(
                head.handle.ticket,
                i.stream,
                generation,
                host.requires_scope(),
            ) {
                return Answered::bare(Outcome::Refused, error);
            }
            match host.hand_in_with_deadline(ask, op_remaining()) {
                Ok((flow, unit)) => {
                    // SAFETY: the caller's answer slot, checked non-NULL by `check_unit_hand_in_in`.
                    unsafe {
                        i.answer.write_unaligned(svc::AuthAnswer {
                            size: size_of::<svc::AuthAnswer>() as u32,
                            flow,
                            unit,
                        });
                    }
                    Answered::bare(Outcome::Ready, "")
                }
                Err(e) => Answered::bare(Outcome::Refused, e),
            }
        },
    )
}

struct HeldRefusal {
    bytes: RefusalBytes,
    fields: Vec<busbar_contract::abi::mechanism::call::Field>,
}

thread_local! {
    /// THE ONE REFUSAL LENT ON THIS THREAD: the caller copies it out before its `unit.refuse`
    /// returns (the SDK's `Services::unit_refuse`), and the next refusal answered on this thread
    /// replaces it. Nothing is kept per connection, so N refusals hold one.
    static LENT_REFUSAL: std::cell::RefCell<Option<Box<HeldRefusal>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn refusals_held() -> usize {
    LENT_REFUSAL.with(|l| usize::from(l.borrow().is_some()))
}

extern "C" fn unit_refuse(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    exact::<svc::UnitRefuseIn>(ctx, input, out, op::UNIT_REFUSE, |i, owner, _, route, h| {
        let host = auth_host(&route);
        let generation = match request_generation(
            owner,
            host.as_ref(),
            &i.unit,
            i.conn,
            i.stream,
            false,
            true,
        ) {
            Ok(generation) => generation,
            Err(error) => return Answered::bare(Outcome::Refused, error),
        };
        if let Some(r) = refused_unit(owner, host.as_ref(), &i.unit) {
            return r;
        }
        if svc::check_unit_refuse_in(&i).is_err() {
            return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED);
        }
        let Some(host) = host else {
            return Answered::bare(Outcome::Refused, AUTH_HANDLE_NOT_SERVED);
        };
        let Some(request) = head_copy(&i.request) else {
            return Answered::bare(Outcome::Refused, AUTH_IN_MALFORMED);
        };
        let framing = match service_framing(owner, i.conn, h.handle.ticket, true) {
            Ok(f) => f,
            Err(e) => return Answered::bare(Outcome::Refused, e),
        };
        if let Err(error) =
            claim_stream_operation(h.handle.ticket, i.stream, generation, host.requires_scope())
        {
            return Answered::bare(Outcome::Refused, error);
        }
        let bytes = match host.refuse(RefuseAsk {
            owner,
            generation,
            unit: i.unit,
            cause: i.cause,
            line: i.line,
            conn: i.conn,
            stream: i.stream,
            framing,
            request,
        }) {
            Ok(b) => b,
            Err(e) => return Answered::bare(Outcome::Refused, e),
        };
        let fields = bytes
            .fields
            .iter()
            .map(|(n, v)| busbar_contract::abi::mechanism::call::Field {
                name: AbiStr {
                    ptr: n.as_ptr(),
                    len: n.len(),
                },
                value: AbiStr {
                    ptr: v.as_ptr(),
                    len: v.len(),
                },
            })
            .collect();
        let held = Box::new(HeldRefusal { bytes, fields });
        let answer = svc::RefusalAnswer {
            size: size_of::<svc::RefusalAnswer>() as u32,
            status: held.bytes.status,
            _reserved: 0,
            fields: if held.fields.is_empty() {
                std::ptr::null()
            } else {
                held.fields.as_ptr()
            },
            fields_len: held.fields.len(),
            body: Blob {
                ptr: if held.bytes.body.is_empty() {
                    std::ptr::null()
                } else {
                    held.bytes.body.as_ptr()
                },
                len: held.bytes.body.len(),
                fmt: if held.bytes.body.is_empty() {
                    busbar_contract::abi::mechanism::call::BLOB_ABSENT
                } else {
                    busbar_contract::abi::mechanism::call::BLOB_OCTETS
                },
                flags: 0,
            },
        };
        LENT_REFUSAL.with(|l| *l.borrow_mut() = Some(held));
        // SAFETY: the caller's answer slot, checked non-NULL by `check_unit_refuse_in`; what it
        // names is lent above until the next refusal on this thread.
        unsafe { i.answer.write_unaligned(answer) };
        Answered::bare(Outcome::Ready, "")
    })
}

const EMIT_NOTHING: &str = "session.emit names an open session and something to write";

service! {
    ticket_mint, scoped, op::TICKET_MINT, TicketMintIn, |served, route, head, caller, i| {
        let Some(record) = blob_of(i.record, "ticket_mint.record") else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        if svc::check_ticket_mint_in(&i).is_err() {
            return Answered::bare(Outcome::Refused, MINT_OUT_OF_RANGE);
        }
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[&i.ttl_secs.to_le_bytes(), &record]);
            serve(served.store, &route, &head, req, Some(&i.into), |_| {
                Ran::Now(provider.ticket_mint(caller, unit, i.ttl_secs, &record))
            })
        }
    }
}

const MINT_OUT_OF_RANGE: &str =
    "ticket.mint asks a lifetime of at least one second and a record within the cap";

service! {
    ticket_take, scoped, op::TICKET_TAKE, TicketTakeIn, |served, route, head, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            serve(
                served.store,
                &route,
                &head,
                Fp::of(&[]),
                Some(&i.into),
                |_| Ran::Now(provider.ticket_take(caller, unit)),
            )
        }
    }
}

service! {
    random_fill, slot, op::RANDOM_FILL, RandomFillIn, |served, route, head, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        if check_random_fill_in(&i).is_err() {
            return Answered::bare(Outcome::Refused, FILL_OUT_OF_RANGE);
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[&i.len.to_le_bytes()]);
            serve(served.store, &route, &head, req, Some(&i.into), |_| {
                Ran::Now(provider.random_fill(i.len))
            })
        }
    }
}

service! {
    unit_nest, scoped, op::UNIT_NEST, UnitNestIn, |served, route, head, caller, i| {
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
        let provider = served.provider;
        let req = Fp::of(&[verb.as_bytes(), target.as_bytes(), &body]);
        let ask = NestAsk { verb, target, body };
        // SAFETY: `into` checked above; the caller's buffers, where the whole reply goes.
        unsafe {
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.unit_nest(caller, unit, ask, later)
            })
        }
    }
}

pub const WORK_RECORD_TOO_LONG: &str = "the work record is longer than MAX_WORK_RECORD";

service! {
    work_open, scoped, op::WORK_OPEN, WorkOpenIn, |served, route, head, caller, i| {
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
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[kind.as_bytes(), &record]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.work_open(caller, unit, &kind, &record, later)
            })
        }
    }
}

service! {
    work_find, scoped, op::WORK_FIND, WorkFindIn, |served, route, head, caller, i| {
        let Some(reference) = bytes_of(i.reference, "work_find.reference") else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[&reference]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.work_find(caller, unit, &reference, later)
            })
        }
    }
}

service! {
    work_settle, scoped, op::WORK_SETTLE, WorkSettleIn, |served, route, head, caller, i| {
        let Some(record) = blob_of(i.record, "work_settle.record") else {
            return Answered::fault();
        };
        if check_work_record(&i.record).is_err() {
            return Answered::bare(Outcome::Refused, WORK_RECORD_TOO_LONG);
        }
        // The unit this crossing serves: the kernel judges the settle against it.
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[&i.handle.to_le_bytes(), &record]);
            pended(&served, &route, &head, req, None, |later| {
                provider.work_settle(caller, unit, i.handle, &record, later)
            })
        }
    }
}

service! {
    work_resume, scoped, op::WORK_RESUME, WorkResumeIn, |served, route, head, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers.
        unsafe {
            let req = Fp::of(&[&i.handle.to_le_bytes()]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.work_resume(caller, unit, i.handle, later)
            })
        }
    }
}

pub const NO_VERIFY_KEY: &str = "a verify call names its key";

pub const HOOK_UNKNOWN_STAGE: &str = "the hook stage is neither a gate nor a rewrite";

pub const HOOK_FROM_PAST_CAP: &str = "a rewrite chain resumes no further than HOOK_FROM_MAX";

pub const HOOK_GATE_RESUMED: &str = "a gate is never resumed";

pub const HOOK_NO_PROMPT: &str = "a hook call states its prompt view";

service! {
    verify_lookup, scoped, op::VERIFY_LOOKUP, VerifyLookupIn, |served, route, head, caller, i| {
        let Some(key) = bytes_of(i.key, "verify_lookup.key") else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        if key.is_empty() {
            return Answered::bare(Outcome::Refused, NO_VERIFY_KEY);
        }
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers, where the entry goes.
        unsafe {
            let req = Fp::of(&[&key]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.verify_lookup(caller, &key, later)
            })
        }
    }
}

service! {
    verify_store, scoped, op::VERIFY_STORE, VerifyStoreIn, |served, route, head, caller, i| {
        let (Some(key), Some(entry)) = (
            bytes_of(i.key, "verify_store.key"),
            blob_of(i.entry, "verify_store.entry"),
        ) else {
            return Answered::fault();
        };
        if key.is_empty() {
            return Answered::bare(Outcome::Refused, NO_VERIFY_KEY);
        }
        let provider = served.provider;
        // SAFETY: no buffer is named.
        unsafe {
            let req = Fp::of(&[&key, &entry, &i.ttl_ms.to_le_bytes()]);
            serve(served.store, &route, &head, req, None, |_| {
                Ran::Now(provider.verify_store(caller, &key, &entry, i.ttl_ms))
            })
        }
    }
}

service! {
    content_scan, scoped, op::CONTENT_SCAN, ContentScanIn, |served, route, head, caller, i| {
        let Some(content) = blob_of(i.content, "content_scan.content") else {
            return Answered::fault();
        };
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers, where rewritten content goes.
        unsafe {
            let req = Fp::of(&[&content]);
            pended(&served, &route, &head, req, Some(&i.into), |later| {
                provider.content_scan(caller, unit, &content, later)
            })
        }
    }
}

type PromptCopy = (Option<String>, Vec<(String, String)>);

/// The caller's prompt view, copied: `None` for a view that breaks its rules (a NULL list with a
/// count, a count past the hard maximum or contradicting the list, a string NULL with a length or
/// not UTF-8).
///
/// # Safety
/// `prompt` is non-NULL and, with every list and string it names, the caller's, live for the call.
unsafe fn prompt_of(prompt: *const busbar_contract::abi::hook::PromptView) -> Option<PromptCopy> {
    // SAFETY: the caller's contract.
    let view = unsafe { prompt.read_unaligned() };
    busbar_contract::abi::hook::validate::check_prompt_view(&view).ok()?;
    let system = if view.system.ptr.is_null() {
        None
    } else {
        Some(text_of(view.system, "hook_call.prompt.system")?)
    };
    let mut messages = Vec::with_capacity(view.messages_len);
    for n in 0..view.messages_len {
        // SAFETY: a checked list of `messages_len` views of the caller's (non-NULL for a count).
        let m = unsafe { view.messages.add(n).read_unaligned() };
        messages.push((
            text_of(m.role, "hook_call.prompt.role")?,
            text_of(m.text, "hook_call.prompt.text")?,
        ));
    }
    Some((system, messages))
}

service! {
    hook_call, scoped, op::HOOK_CALL, HookCallIn, |served, route, head, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        if let Err(f) = check_hook_call_in(&i) {
            return Answered::bare(
                Outcome::Refused,
                match f.rule {
                    check::Rule::UnknownCode => HOOK_UNKNOWN_STAGE,
                    check::Rule::OverMax => HOOK_FROM_PAST_CAP,
                    check::Rule::Contradiction => HOOK_GATE_RESUMED,
                    _ => HOOK_NO_PROMPT,
                },
            );
        }
        // SAFETY: checked non-NULL above; the caller's view, live for the call; copied before
        // any pend.
        let Some((system, messages)) = (unsafe { prompt_of(i.prompt) }) else {
            return Answered::fault();
        };
        let mut req = Fp::EMPTY
            .with(&i.stage.to_le_bytes())
            .with(&i.from.to_le_bytes())
            .with(&[u8::from(system.is_some())])
            .with(system.as_deref().unwrap_or_default().as_bytes());
        for (role, text) in &messages {
            req = req.with(role.as_bytes()).with(text.as_bytes());
        }
        let ask = HookAsk {
            stage: i.stage,
            from: i.from,
            system,
            messages,
        };
        let unit = serving_unit();
        let provider = served.provider;
        // SAFETY: `into` checked above; the caller's buffers, where the reply goes.
        unsafe {
            pended(&served, &route, &head, req.0, Some(&i.into), |later| {
                provider.hook_call(caller, unit, ask, later)
            })
        }
    }
}

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
            let armed = super::conn_services::armed(ctx);
            let binding = super::export_bindings::current();
            let verdict = armed
                .and_then(|original| {
                    binding
                        .as_ref()
                        .map_or(Some(original), |binding| binding.conn.as_ref())
                })
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

service! {
    snapshot_read, scoped, op::SNAPSHOT_READ, SnapshotReadIn, |served, _, _, caller, i| {
        if check_bufs(&i.into).is_err() {
            return Answered::fault();
        }
        if svc::check_snapshot_read_in(&i).is_err() {
            return Answered::fault();
        }
        match served.provider.snapshot_read(caller, i.scope) {
            Snapshot::Families(families) => {
                let needed = super::snapshot::size_of_layout(&families);
                if needed > i.into.cap {
                    return Answered {
                        needed_bytes: needed as u64,
                        ..Answered::bare(Outcome::Failed, SHORT)
                    };
                }
                // SAFETY: `into` was checked above (a capacity never behind NULL, the
                // alignment the layout needs), and the layout fits its capacity.
                let used = unsafe { super::snapshot::lay_out(&families, i.into.buf) };
                Answered {
                    value: families.len() as u64,
                    len: used as u64,
                    ..Answered::bare(Outcome::Ready, "")
                }
            }
            Snapshot::NotReady => Answered::bare(Outcome::Failed, SNAPSHOT_NOT_READY),
            Snapshot::Refused(why) => Answered::bare(Outcome::Refused, why),
        }
    }
}

#[path = "completion_store.rs"]
mod completion_store;
#[path = "inspection_store.rs"]
mod inspection_store;

#[path = "conditional_store.rs"]
mod conditional_store;
