// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES (`BUSBAR-1.6.0.md` THE DESIGN, host services): every host service a plugin calls
//! beyond the connector, in ONE table, [`HostSlots`], on the connector's call shape. This file also
//! holds the call shape both tables share: [`ServiceFn`], [`ServiceHead`] and [`ServiceOut`].
//!
//! THE CALL SHAPE. `svc(ctx, in, out)`, `extern "C"` (a panic escaping it aborts), answering the
//! mechanism's [`RawOutcome`]. Every `in` leads with a [`ServiceHead`] and its
//! [`CompletionHandle`]. A service that cannot finish answers PENDING and wakes the handle's
//! ticket; on resume the plugin re-issues the SAME handle and receives the stored result. The host
//! never runs a service twice for one handle.
//!
//! THE SHORT-BUFFER RULE FOR SERVICES. The caller is the plugin, so a service writes its result
//! into PLUGIN buffers its `in` names ([`ServiceBufs`]: bytes, and the spans that name ranges of
//! them). [`ServiceOut`] carries a `needed_*` per dimension. A plugin declares its largest buffers
//! at `open` and preallocates them. A short answer is FAILED with every `needed_*` at its full size,
//! at least one above its capacity, and nothing applied or written. The PLUGIN re-calls once, on the
//! same handle, with at least `needed_*`; the re-call reads the stored result and acts again on
//! nothing. A second short answer on that handle is FAULT for the service call, and the plugin's op
//! that made it answers FAULT. The mechanism's statement of the rule for ops is on
//! [`OutHead`](crate::abi::mechanism::call::OutHead); this is its form for services.
//!
//! A SERVICE THAT MAY PEND ([`may_pend`]) is callable only inside a ticketed op. A call made with
//! [`Ticket::NONE`](crate::abi::mechanism::ticket::Ticket::NONE) (a pure op, or any call with no
//! ticket) is REFUSED, never PENDING.
//!
//! ANSWER VALIDATORS. Each shape has its `check_<op>` beside it: the caller's check of the host's
//! answer, built from the shared helpers in `abi/mechanism/check.rs`. [`check_head`] and
//! [`check_bufs`] are the host's checks of the caller's `in`.

use std::os::raw::c_void;

use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, Span};
use crate::abi::mechanism::check::{self, fault, Dim, Fault, Filled, Rule, MAX_BYTES};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx};

/// A host service: `svc(ctx, in, out)`. `extern "C"`: a panic escaping it aborts.
pub type ServiceFn =
    extern "C" fn(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome;

/// The head of every service `in`, in either table.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceHead {
    /// `size_of` the whole `in`.
    pub size: u32,
    /// The service's index in its table.
    pub op: u32,
    /// The completion handle; on resume the plugin re-issues the same one.
    pub handle: CompletionHandle,
}

/// Every service's `out`, in either table. The host writes it whole.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceOut {
    /// `size_of::<ServiceOut>()`.
    pub size: u32,
    /// The outcome, mirrored from the return value (the return value is authoritative).
    pub outcome: RawOutcome,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The service's scalar answer (a stream, a verdict, a handle), as each service states.
    pub value: u64,
    /// Bytes written (or moved, for the connector's `READ`/`WRITE`/`RANDOM`).
    pub len: u64,
    /// Spans written.
    pub items: u64,
    /// On a short answer: the full byte size of the result.
    pub needed_bytes: u64,
    /// On a short answer: the full span count of the result.
    pub needed_items: u64,
    /// For FAILED/REFUSED: the reason; never secret material. Valid for the process's life.
    pub error: AbiStr,
}

/// One named range of a result's bytes: a key and a value, each a [`Span`] into the bytes
/// written, or absent (`offset` = [`check::SPAN_ABSENT`], `len` = `0`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemSpan {
    /// The key.
    pub key: Span,
    /// The value.
    pub value: Span,
}

/// The plugin's buffers a service writes its result into, preallocated at the sizes the plugin
/// declared at `open`. Valid until the service completes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceBufs {
    /// The bytes.
    pub buf: *mut u8,
    /// Their capacity.
    pub cap: usize,
    /// The spans.
    pub spans: *mut ItemSpan,
    /// Their capacity, in spans.
    pub spans_cap: usize,
}

/// The most spans one result may carry.
pub const MAX_SPANS: u64 = 1024;

/// The index of each service in [`HostSlots`], in table order.
pub mod op {
    /// `clock.now`.
    pub const CLOCK_NOW: u32 = 0;
    /// `records.get`.
    pub const RECORDS_GET: u32 = 1;
    /// `records.list`.
    pub const RECORDS_LIST: u32 = 2;
    /// `records.claim`.
    pub const RECORDS_CLAIM: u32 = 3;
    /// `dest.judge`.
    pub const DEST_JUDGE: u32 = 4;
    /// `sign`.
    pub const SIGN: u32 = 5;
    /// `unit.nest`.
    pub const UNIT_NEST: u32 = 6;
    /// `work.open`.
    pub const WORK_OPEN: u32 = 7;
    /// `work.find`.
    pub const WORK_FIND: u32 = 8;
    /// `work.settle`.
    pub const WORK_SETTLE: u32 = 9;
    /// `work.resume`.
    pub const WORK_RESUME: u32 = 10;
    /// `trust.sight`.
    pub const TRUST_SIGHT: u32 = 11;
    /// `trust.due`.
    pub const TRUST_DUE: u32 = 12;
    /// `verify.lookup`.
    pub const VERIFY_LOOKUP: u32 = 13;
    /// `verify.store`.
    pub const VERIFY_STORE: u32 = 14;
    /// `entitlement.check`.
    pub const ENTITLEMENT_CHECK: u32 = 15;
    /// `content.scan`.
    pub const CONTENT_SCAN: u32 = 16;
    /// `hook.call`.
    pub const HOOK_CALL: u32 = 17;
    /// `random.fill`.
    pub const RANDOM_FILL: u32 = 18;
}

/// How many services [`HostSlots`] holds.
pub const SERVICES: u32 = 19;

/// Whether a service may answer PENDING, and so is callable only inside a ticketed op. `false` for
/// an index past the table.
#[must_use]
pub const fn may_pend(service: u32) -> bool {
    !matches!(
        service,
        op::CLOCK_NOW
            | op::SIGN
            | op::TRUST_DUE
            | op::VERIFY_STORE
            | op::ENTITLEMENT_CHECK
            | op::RANDOM_FILL
    ) && service < SERVICES
}

// ── clock ─────────────────────────────────────────────────────────────────────────────────────

/// `clock.now`'s reading: the kernel's one clock.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClockReading {
    /// `size_of::<ClockReading>()`.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Wall time, nanoseconds since the Unix epoch.
    pub wall_ns: u64,
    /// Monotonic time, nanoseconds since an origin fixed for the process's life.
    pub mono_ns: u64,
}

/// [`op::CLOCK_NOW`]'s `in`. Never pends; the host writes the reading.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClockNowIn {
    /// The head.
    pub head: ServiceHead,
    /// Where the host writes the reading.
    pub reading: *mut ClockReading,
}

// ── records ───────────────────────────────────────────────────────────────────────────────────

/// [`op::RECORDS_GET`]'s `in`: one record of the calling plugin's own record kinds. Reads see the
/// instance's own queued write-behind batch. `value` = [`FOUND`] | [`ABSENT`]; found, span `0`'s
/// value is the record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordsGetIn {
    /// The head.
    pub head: ServiceHead,
    /// The record kind (one the plugin declared).
    pub kind: AbiStr,
    /// The key.
    pub key: AbiStr,
    /// Where the record goes.
    pub into: ServiceBufs,
}

/// [`op::RECORDS_LIST`]'s `in`: the calling plugin's records of one kind under a key prefix, in key
/// order after `after`, at most `limit`. Each span is one record (key and value).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordsListIn {
    /// The head.
    pub head: ServiceHead,
    /// The record kind (one the plugin declared).
    pub kind: AbiStr,
    /// The key prefix; absent = every key.
    pub prefix: AbiStr,
    /// List after this key; absent = from the first.
    pub after: AbiStr,
    /// The most records to answer; `0` = as many as fit [`MAX_SPANS`].
    pub limit: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Where the records go.
    pub into: ServiceBufs,
}

/// [`op::RECORDS_CLAIM`]'s `in`: a one-time put-if-absent with a time to live. The ONE path for
/// approval redemption and replay refusal. `value` = [`CLAIM_WON`] | [`CLAIM_TAKEN`]. The host
/// refuses an `in` that breaks [`check_records_claim_in`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordsClaimIn {
    /// The head.
    pub head: ServiceHead,
    /// The record kind (one the plugin declared).
    pub kind: AbiStr,
    /// The key.
    pub key: AbiStr,
    /// How long the claim stands, in milliseconds. Never `0`: there is no default.
    pub ttl_ms: u64,
}

/// `value` of [`op::RECORDS_GET`]: no such record.
pub const ABSENT: u64 = 0;
/// `value` of [`op::RECORDS_GET`]: the record is in span `0`.
pub const FOUND: u64 = 1;
/// `value` of [`op::RECORDS_CLAIM`]: this call made the claim.
pub const CLAIM_WON: u64 = 1;
/// `value` of [`op::RECORDS_CLAIM`]: the key was already claimed.
pub const CLAIM_TAKEN: u64 = 2;

// ── dest ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::DEST_JUDGE`]'s `in`: judge a destination named inside content against the egress rules of
/// a class (the allow-list, the class, the cloud metadata hosts) without dialing. A refusal decidable
/// from the name answers at once; with [`DEST_RESOLVE`] a name is then resolved (which may pend) and
/// every address it answers is judged. `value` = a `DEST_*` verdict.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DestJudgeIn {
    /// The head.
    pub head: ServiceHead,
    /// The destination, as the content names it (a URL, or `host:port`).
    pub dest: AbiStr,
    /// The egress class whose rules apply; `0` = the host's default.
    pub egress_class: u32,
    /// [`DEST_RESOLVE`].
    pub flags: u32,
}

/// [`DestJudgeIn::flags`]: resolve a name and judge every address it answers; without it the
/// judgement is the name's alone.
pub const DEST_RESOLVE: u32 = 1;

/// `dest.judge` verdict: admissible.
pub const DEST_ALLOWED: u64 = 0;
/// `dest.judge` verdict: not an admitted scheme.
pub const DEST_SCHEME: u64 = 1;
/// `dest.judge` verdict: no usable host.
pub const DEST_NO_HOST: u64 = 2;
/// `dest.judge` verdict: a cloud metadata host, by name, address or list.
pub const DEST_METADATA: u64 = 3;
/// `dest.judge` verdict: an alternate spelling of an address.
pub const DEST_OBFUSCATED: u64 = 4;
/// `dest.judge` verdict: an internal host the class does not admit.
pub const DEST_INTERNAL: u64 = 5;
/// `dest.judge` verdict: plaintext the class does not admit.
pub const DEST_PLAINTEXT: u64 = 6;
/// `dest.judge` verdict: the name did not resolve.
pub const DEST_UNRESOLVABLE: u64 = 7;
/// `dest.judge` verdict: the name resolved to nothing.
pub const DEST_NO_ADDRESSES: u64 = 8;

// ── sign ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::SIGN`]'s `in`: sign bytes with busbar's key under the plugin's declared signing domain and
/// key-id prefix; refused for a plugin that declares none. Span `0`: key = the key id, value = the
/// signature. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignIn {
    /// The head.
    pub head: ServiceHead,
    /// The bytes to sign.
    pub data: Blob,
    /// Where the key id and the signature go.
    pub into: ServiceBufs,
}

// ── unit ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::UNIT_NEST`]'s `in`: run a nested unit on whatever plugin serves the named claim, as a child
/// of the calling unit (its principal, its audit correlation, its admission), depth-capped. The reply
/// comes back whole: `value` = its status, the bytes its body, the spans its fields.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitNestIn {
    /// The head.
    pub head: ServiceHead,
    /// The claim's verb.
    pub verb: AbiStr,
    /// The claim's target.
    pub target: AbiStr,
    /// The body.
    pub body: Blob,
    /// Where the reply goes.
    pub into: ServiceBufs,
}

// ── work ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::WORK_OPEN`]'s `in`: open a durable work handle. `value` = the handle.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkOpenIn {
    /// The head.
    pub head: ServiceHead,
    /// The work kind (one the plugin declared).
    pub kind: AbiStr,
    /// The handle's record.
    pub record: Blob,
}

/// [`op::WORK_FIND`]'s `in`: the scoped lookup. Every denial answers alike ([`ABSENT`]); found,
/// `value` = the handle and span `0`'s value its record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkFindIn {
    /// The head.
    pub head: ServiceHead,
    /// The reference the caller holds.
    pub reference: AbiStr,
    /// Where the record goes.
    pub into: ServiceBufs,
}

/// [`op::WORK_SETTLE`]'s `in`: settle a handle with its final record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkSettleIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// The final record.
    pub record: Blob,
}

/// [`op::WORK_RESUME`]'s `in`: bind the handle's record to the calling unit. A continuation is a
/// NEW unit, with its own arrival, admission and window; this only binds the record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkResumeIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// Where the record goes.
    pub into: ServiceBufs,
}

// ── trust ─────────────────────────────────────────────────────────────────────────────────────

/// [`op::TRUST_SIGHT`]'s `in`: report a counterparty's catalogue hash; the kernel judges it.
/// `value` = a `TRUST_*` verdict.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustSightIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// Its catalogue hash.
    pub catalogue_hash: AbiStr,
}

/// [`op::TRUST_DUE`]'s `in`: the counterparties the kernel's `tick` marked for re-verification,
/// one span each (key = the counterparty). Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustDueIn {
    /// The head.
    pub head: ServiceHead,
    /// Where the names go.
    pub into: ServiceBufs,
}

/// `trust.sight` verdict: never seen before.
pub const TRUST_NEW: u64 = 1;
/// `trust.sight` verdict: the pinned catalogue.
pub const TRUST_SAME: u64 = 2;
/// `trust.sight` verdict: the catalogue moved from its pin.
pub const TRUST_DRIFTED: u64 = 3;
/// `trust.sight` verdict: the counterparty is quarantined.
pub const TRUST_QUARANTINED: u64 = 4;

// ── verify ────────────────────────────────────────────────────────────────────────────────────

/// [`op::VERIFY_LOOKUP`]'s `in`: the host-side verify cache, single-flight. `value` =
/// [`VERIFY_HIT`] (span `0`'s value is the entry), [`VERIFY_LEAD`] (the caller fetches and stores)
/// or [`VERIFY_FOLLOW`] (another caller leads; the answer pends until it stores).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyLookupIn {
    /// The head.
    pub head: ServiceHead,
    /// The cache key.
    pub key: AbiStr,
    /// Where the entry goes.
    pub into: ServiceBufs,
}

/// [`op::VERIFY_STORE`]'s `in`: store the entry a leader fetched; releases its followers. Never
/// pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyStoreIn {
    /// The head.
    pub head: ServiceHead,
    /// The cache key.
    pub key: AbiStr,
    /// The entry.
    pub entry: Blob,
    /// How long it stands, in milliseconds; `0` = the host's default.
    pub ttl_ms: u64,
}

/// `verify.lookup`: a cached entry.
pub const VERIFY_HIT: u64 = 1;
/// `verify.lookup`: the caller leads.
pub const VERIFY_LEAD: u64 = 2;
/// `verify.lookup`: the caller followed a leader, whose entry is in span `0`.
pub const VERIFY_FOLLOW: u64 = 3;

// ── entitlement ───────────────────────────────────────────────────────────────────────────────

/// [`op::ENTITLEMENT_CHECK`]'s `in`: whether the caller is entitled to the target (the catalogue
/// visibility filter). `value` = [`ENTITLED`] | [`NOT_ENTITLED`]. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EntitlementCheckIn {
    /// The head.
    pub head: ServiceHead,
    /// The target.
    pub target: AbiStr,
}

/// `entitlement.check`: not entitled.
pub const NOT_ENTITLED: u64 = 0;
/// `entitlement.check`: entitled.
pub const ENTITLED: u64 = 1;

// ── random ────────────────────────────────────────────────────────────────────────────────────

/// The most bytes one `random.fill` answers.
pub const MAX_RANDOM_FILL: u64 = 1024;

/// [`op::RANDOM_FILL`]'s `in`: `len` bytes from the kernel's CSPRNG, written into `into`'s bytes
/// (no span); READY `value` `0`, `len` exactly the bytes asked. `len` is `1..=`[`MAX_RANDOM_FILL`];
/// anything else is REFUSED before a byte is drawn. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RandomFillIn {
    /// The head.
    pub head: ServiceHead,
    /// How many bytes.
    pub len: u64,
    /// Where they go.
    pub into: ServiceBufs,
}

/// `random.fill`'s `in`, before any byte is drawn: a fill asks for at least one byte and at most
/// [`MAX_RANDOM_FILL`]. The host REFUSES an `in` that breaks this.
///
/// # Errors
///
/// [`Rule::Missing`] for `len == 0`; [`Rule::OverMax`] above [`MAX_RANDOM_FILL`].
pub const fn check_random_fill_in(i: &RandomFillIn) -> Result<(), Fault> {
    if i.len == 0 {
        return Err(fault(Rule::Missing, "random_fill.len"));
    }
    if i.len > MAX_RANDOM_FILL {
        return Err(fault(Rule::OverMax, "random_fill.len"));
    }
    Ok(())
}

// ── content ───────────────────────────────────────────────────────────────────────────────────

/// [`op::CONTENT_SCAN`]'s `in`: pass a piece of in-session content through the gate that governs
/// it. `value` = [`CONTENT_PASS`] | [`CONTENT_BLOCK`]; the bytes, when written, are the content as
/// the gate rewrote it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ContentScanIn {
    /// The head.
    pub head: ServiceHead,
    /// The content.
    pub content: Blob,
    /// Where rewritten content goes.
    pub into: ServiceBufs,
}

/// `content.scan`: the content passes.
pub const CONTENT_PASS: u64 = 0;
/// `content.scan`: the gate blocked it.
pub const CONTENT_BLOCK: u64 = 1;

// ── hook ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::HOOK_CALL`]'s `in`: run a hook stage for an in-session sub-operation, over the hook kind's
/// own [`RequestView`](crate::abi::hook::RequestView). `value` = the stage's decision, as the hook
/// kind numbers it; the bytes and spans are its reply.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookCallIn {
    /// The head.
    pub head: ServiceHead,
    /// The stage, as the hook kind numbers it.
    pub stage: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The view.
    pub view: *const crate::abi::hook::RequestView,
    /// Where the reply goes.
    pub into: ServiceBufs,
}

// ── the table ─────────────────────────────────────────────────────────────────────────────────

/// THE HOST SERVICES TABLE: one [`ServiceFn`] per [`op`], in index order. A NULL slot is a service
/// this host does not offer, and a plugin that needs it refuses to open.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostSlots {
    /// `size_of::<HostSlots>()`.
    pub size: u32,
    /// [`SERVICES`].
    pub slots: u32,
    /// [`op::CLOCK_NOW`], in [`ClockNowIn`].
    pub clock_now: Option<ServiceFn>,
    /// [`op::RECORDS_GET`], in [`RecordsGetIn`].
    pub records_get: Option<ServiceFn>,
    /// [`op::RECORDS_LIST`], in [`RecordsListIn`].
    pub records_list: Option<ServiceFn>,
    /// [`op::RECORDS_CLAIM`], in [`RecordsClaimIn`].
    pub records_claim: Option<ServiceFn>,
    /// [`op::DEST_JUDGE`], in [`DestJudgeIn`].
    pub dest_judge: Option<ServiceFn>,
    /// [`op::SIGN`], in [`SignIn`].
    pub sign: Option<ServiceFn>,
    /// [`op::UNIT_NEST`], in [`UnitNestIn`].
    pub unit_nest: Option<ServiceFn>,
    /// [`op::WORK_OPEN`], in [`WorkOpenIn`].
    pub work_open: Option<ServiceFn>,
    /// [`op::WORK_FIND`], in [`WorkFindIn`].
    pub work_find: Option<ServiceFn>,
    /// [`op::WORK_SETTLE`], in [`WorkSettleIn`].
    pub work_settle: Option<ServiceFn>,
    /// [`op::WORK_RESUME`], in [`WorkResumeIn`].
    pub work_resume: Option<ServiceFn>,
    /// [`op::TRUST_SIGHT`], in [`TrustSightIn`].
    pub trust_sight: Option<ServiceFn>,
    /// [`op::TRUST_DUE`], in [`TrustDueIn`].
    pub trust_due: Option<ServiceFn>,
    /// [`op::VERIFY_LOOKUP`], in [`VerifyLookupIn`].
    pub verify_lookup: Option<ServiceFn>,
    /// [`op::VERIFY_STORE`], in [`VerifyStoreIn`].
    pub verify_store: Option<ServiceFn>,
    /// [`op::ENTITLEMENT_CHECK`], in [`EntitlementCheckIn`].
    pub entitlement_check: Option<ServiceFn>,
    /// [`op::CONTENT_SCAN`], in [`ContentScanIn`].
    pub content_scan: Option<ServiceFn>,
    /// [`op::HOOK_CALL`], in [`HookCallIn`].
    pub hook_call: Option<ServiceFn>,
    /// [`op::RANDOM_FILL`], in [`RandomFillIn`].
    pub random_fill: Option<ServiceFn>,
}

// ── the host's checks of an `in` ──────────────────────────────────────────────────────────────

/// The head of an `in` for `service`, whose `in` type is `in_size` bytes: the op is the slot's, and
/// the stated size covers the type.
///
/// # Errors
///
/// [`Rule::Contradiction`] for another op; [`Rule::Foreign`] for a short `in`.
pub const fn check_head(head: &ServiceHead, service: u32, in_size: usize) -> Result<(), Fault> {
    if head.op != service {
        return Err(fault(Rule::Contradiction, "service.head.op"));
    }
    if (head.size as usize) < in_size {
        return Err(fault(Rule::Foreign, "service.head.size"));
    }
    Ok(())
}

/// The caller's buffers: a capacity never comes with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn check_bufs(into: &ServiceBufs) -> Result<(), Fault> {
    check::listed(into.buf.cast_const(), into.cap, "service.into.buf")?;
    check::listed(
        into.spans.cast_const(),
        into.spans_cap,
        "service.into.spans",
    )
}

/// A `records.claim` `in`: a claim states how long it stands; a zero time to live is refused, as
/// there is no default to fall back on.
///
/// # Errors
///
/// [`Rule::Missing`] for `ttl_ms == 0`.
pub const fn check_records_claim_in(i: &RecordsClaimIn) -> Result<(), Fault> {
    if i.ttl_ms == 0 {
        return Err(fault(Rule::Missing, "records_claim.ttl_ms"));
    }
    Ok(())
}

// ── the caller's checks of an answer ──────────────────────────────────────────────────────────

/// What a service's answer may carry beyond the common rules.
#[derive(Debug, Clone, Copy)]
struct Shape {
    /// The buffers the `in` named; `None` = the service writes no buffer.
    into: Option<ServiceBufs>,
    /// The READY `value`s the service answers, as `lo..=hi`.
    values: (u64, u64),
    /// Whether the service may answer PENDING.
    may_pend: bool,
}

/// THE COMMON ANSWER RULES, every service: the return value is authoritative and the mirrored
/// `outcome` agrees with it; `size` is this `out`'s; PENDING only from a service that may pend and on
/// a real ticket; the short-buffer rule over the two dimensions; REFUSED carries no `needed_*`; a
/// READY `value` in the service's range; every span written inside the bytes written.
fn answer(
    ret: RawOutcome,
    head: &ServiceHead,
    out: &ServiceOut,
    shape: Shape,
) -> Result<Filled, Fault> {
    let outcome = ret.outcome();
    if out.outcome.outcome() != outcome {
        return Err(fault(Rule::Contradiction, "service.out.outcome"));
    }
    if out.size as usize != core::mem::size_of::<ServiceOut>() {
        return Err(fault(Rule::Foreign, "service.out.size"));
    }
    if outcome == Outcome::Pending && (!shape.may_pend || head.handle.ticket.is_none()) {
        return Err(fault(Rule::Contradiction, "service.out.pending"));
    }
    let (cap, spans_cap) = shape
        .into
        .map_or((0, 0), |b| (b.cap as u64, b.spans_cap as u64));
    let filled = check::results(
        outcome,
        "service.out",
        &[
            Dim {
                written: out.len,
                needed: out.needed_bytes,
                cap,
                max: MAX_BYTES,
                field: "service.out.needed_bytes",
            },
            Dim {
                written: out.items,
                needed: out.needed_items,
                cap: spans_cap,
                max: MAX_SPANS,
                field: "service.out.needed_items",
            },
        ],
    )?;
    if outcome == Outcome::Ready {
        check::code(
            out.value,
            shape.values.0,
            shape.values.1,
            "service.out.value",
        )?;
        if let Some(b) = shape.into {
            // SAFETY: the caller's own spans buffer, `spans_cap` long; `reported` checks the count
            // against it before building the slice.
            let spans = unsafe {
                check::reported(
                    b.spans.cast_const(),
                    out.items,
                    spans_cap,
                    "service.out.items",
                )
            }?;
            for s in spans {
                check::span(s.key.offset, s.key.len, out.len, "service.out.span.key")?;
                check::span(
                    s.value.offset,
                    s.value.len,
                    out.len,
                    "service.out.span.value",
                )?;
            }
        }
    }
    Ok(filled)
}

/// A service with no buffer and no scalar beyond `values`.
const fn bare(service: u32, values: (u64, u64)) -> Shape {
    Shape {
        into: None,
        values,
        may_pend: may_pend(service),
    }
}

/// A service writing into `into`.
const fn into(service: u32, into: ServiceBufs, values: (u64, u64)) -> Shape {
    Shape {
        into: Some(into),
        values,
        may_pend: may_pend(service),
    }
}

/// Any `value`.
const ANY: (u64, u64) = (0, u64::MAX);

/// `clock.now`'s answer: the common rules, and on READY a reading of this layout's size.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_clock_now(i: &ClockNowIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    let filled = answer(ret, &i.head, out, bare(op::CLOCK_NOW, (0, 0)))?;
    if ret.outcome() == Outcome::Ready {
        if i.reading.is_null() {
            return Err(fault(Rule::NullWithCount, "clock_now.reading"));
        }
        // SAFETY: the caller's own reading slot, checked non-NULL.
        let size = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*i.reading).size)) };
        if size as usize != core::mem::size_of::<ClockReading>() {
            return Err(fault(Rule::Foreign, "clock_now.reading.size"));
        }
    }
    Ok(filled)
}

/// `records.get`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_records_get(
    i: &RecordsGetIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        into(op::RECORDS_GET, i.into, (ABSENT, FOUND)),
    )
}

/// `records.list`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_records_list(
    i: &RecordsListIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::RECORDS_LIST, i.into, (0, 0)))
}

/// `records.claim`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_records_claim(
    i: &RecordsClaimIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::RECORDS_CLAIM, (CLAIM_WON, CLAIM_TAKEN)),
    )
}

/// `dest.judge`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_dest_judge(
    i: &DestJudgeIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::DEST_JUDGE, (DEST_ALLOWED, DEST_NO_ADDRESSES)),
    )
}

/// `sign`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_sign(i: &SignIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::SIGN, i.into, (0, 0)))
}

/// `unit.nest`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_unit_nest(i: &UnitNestIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::UNIT_NEST, i.into, ANY))
}

/// `work.open`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_work_open(i: &WorkOpenIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, bare(op::WORK_OPEN, (1, u64::MAX)))
}

/// `work.find`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_work_find(i: &WorkFindIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::WORK_FIND, i.into, ANY))
}

/// `work.settle`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_work_settle(
    i: &WorkSettleIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, bare(op::WORK_SETTLE, (0, 0)))
}

/// `work.resume`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_work_resume(
    i: &WorkResumeIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::WORK_RESUME, i.into, (0, 0)))
}

/// `trust.sight`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_sight(
    i: &TrustSightIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::TRUST_SIGHT, (TRUST_NEW, TRUST_QUARANTINED)),
    )
}

/// `trust.due`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_due(i: &TrustDueIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::TRUST_DUE, i.into, (0, 0)))
}

/// `verify.lookup`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_verify_lookup(
    i: &VerifyLookupIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        into(op::VERIFY_LOOKUP, i.into, (VERIFY_HIT, VERIFY_FOLLOW)),
    )
}

/// `verify.store`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_verify_store(
    i: &VerifyStoreIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, bare(op::VERIFY_STORE, (0, 0)))
}

/// `entitlement.check`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_entitlement_check(
    i: &EntitlementCheckIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::ENTITLEMENT_CHECK, (NOT_ENTITLED, ENTITLED)),
    )
}

/// `random.fill`'s answer: the common rules, and on READY exactly the `len` bytes asked, no span.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_random_fill(
    i: &RandomFillIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(ret, &i.head, out, into(op::RANDOM_FILL, i.into, (0, 0)))?;
    if ret.outcome() == Outcome::Ready && (out.len != i.len || out.items != 0) {
        return Err(fault(Rule::Contradiction, "random_fill.out.len"));
    }
    Ok(filled)
}

/// `content.scan`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_content_scan(
    i: &ContentScanIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        into(op::CONTENT_SCAN, i.into, (CONTENT_PASS, CONTENT_BLOCK)),
    )
}

/// `hook.call`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_hook_call(i: &HookCallIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, into(op::HOOK_CALL, i.into, ANY))
}

#[cfg(test)]
#[path = "../tests/host_service_tests.rs"]
mod tests;
