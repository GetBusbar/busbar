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

use crate::abi::auth::FieldSpan;
use crate::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, RawOutcome, Span};
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

impl ServiceHead {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `ServiceHead { …, ..ServiceHead::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        size: 0,
        op: 0,
        handle: CompletionHandle::ZERO,
    };
}

/// Every service's `out`, in either table. The caller states its `size`; the host writes
/// `min(size, its own)` bytes of it ([`write_out`]), and refuses an `out` below
/// [`SERVICE_OUT_V1`] before the service runs ([`lent_out`]), so an `out` may grow by appending
/// and an older caller's smaller one is never overrun.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceOut {
    /// `size_of::<ServiceOut>()`: the caller's, as it lends it.
    pub size: u32,
    /// The outcome, mirrored from the return value (the return value is authoritative).
    pub outcome: RawOutcome,
    /// `io.ends` on a spawned program's handle: `1` once the program itself has exited (its exit
    /// code is then `value`), `0` while it runs. Every other service, and every other handle,
    /// answers `0`. Claimed from the first padding byte, which every host has always written as
    /// zero, so a caller on an older host reads `0`, "not exited", and falls back to its pipe.
    pub exited: u8,
    /// Alignment padding.
    pub _reserved: [u8; 2],
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

/// The size of the first [`ServiceOut`]: every caller lends at least this many bytes, and an
/// `out` stating less is REFUSED with nothing written ([`lent_out`]).
pub const SERVICE_OUT_V1: usize = 64;

/// How many bytes of the caller's `out` the host may write: its stated `size` capped at the host's
/// own `size_of::<ServiceOut>()`, or `None` for an `out` stating less than [`SERVICE_OUT_V1`],
/// which the host REFUSES before the service runs and never writes.
///
/// # Safety
///
/// `out` is non-NULL and the caller's, its leading `size` readable.
#[must_use]
pub unsafe fn lent_out(out: *const ServiceOut) -> Option<usize> {
    // SAFETY: the caller's `out`, its leading `u32` readable (the contract above).
    let stated = unsafe { out.cast::<u32>().read_unaligned() } as usize;
    (stated >= SERVICE_OUT_V1).then(|| stated.min(size_of::<ServiceOut>()))
}

/// Write `o` into the caller's `out`, the first `lent` bytes of it ([`lent_out`]); `o.size` is set
/// to the bytes written. Nothing past `lent` is touched.
///
/// # Safety
///
/// `out` is non-NULL and the caller's, writable for `lent` bytes, and `lent` is at most
/// `size_of::<ServiceOut>()`.
pub unsafe fn write_out(out: *mut ServiceOut, mut o: ServiceOut, lent: usize) {
    let lent = lent.min(size_of::<ServiceOut>());
    o.size = lent as u32;
    // SAFETY: `o` is a whole `ServiceOut` and `out` is writable for `lent <= size_of` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(std::ptr::from_ref(&o).cast::<u8>(), out.cast::<u8>(), lent);
    }
}

impl ServiceOut {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `ServiceOut { …, ..ServiceOut::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        size: 0,
        outcome: RawOutcome(0),
        exited: 0,
        _reserved: [0; 2],
        value: 0,
        len: 0,
        items: 0,
        needed_bytes: 0,
        needed_items: 0,
        error: AbiStr::ZERO,
    };
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

impl ItemSpan {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `ItemSpan { …, ..ItemSpan::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        key: Span::ZERO,
        value: Span::ZERO,
    };
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

impl ServiceBufs {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `ServiceBufs { …, ..ServiceBufs::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        buf: std::ptr::null_mut(),
        cap: 0,
        spans: std::ptr::null_mut(),
        spans_cap: 0,
    };
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
    /// `need.admit`.
    pub const NEED_ADMIT: u32 = 19;
    /// `trust.verify`.
    pub const TRUST_VERIFY: u32 = 20;
    /// `records.secret`.
    pub const RECORDS_SECRET: u32 = 21;
    /// `disk.append`.
    pub const DISK_APPEND: u32 = 22;
    /// `snapshot.read`.
    pub const SNAPSHOT_READ: u32 = 23;
    /// `trust.sight_item`.
    pub const TRUST_SIGHT_ITEM: u32 = 24;
    /// `trust.serves`.
    pub const TRUST_SERVES: u32 = 25;
    /// `trust.decide`.
    pub const TRUST_DECIDE: u32 = 26;
    /// `trust.state`.
    pub const TRUST_STATE: u32 = 27;
    /// `session.emit`.
    pub const SESSION_EMIT: u32 = 28;
    /// `auth.call`.
    pub const AUTH_CALL: u32 = 29;
    /// `unit.hand_in`.
    pub const UNIT_HAND_IN: u32 = 30;
    /// `unit.refuse`.
    pub const UNIT_REFUSE: u32 = 31;
    /// `ticket.mint`.
    pub const TICKET_MINT: u32 = 32;
    /// `ticket.take`.
    pub const TICKET_TAKE: u32 = 33;
}

/// How many services [`HostSlots`] holds.
pub const SERVICES: u32 = 34;

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
            | op::NEED_ADMIT
            | op::TRUST_VERIFY
            | op::SNAPSHOT_READ
            | op::TRUST_SIGHT_ITEM
            | op::TRUST_SERVES
            | op::TRUST_DECIDE
            | op::TRUST_STATE
            | op::SESSION_EMIT
            | op::UNIT_HAND_IN
            | op::UNIT_REFUSE
            | op::TICKET_MINT
            | op::TICKET_TAKE
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

/// [`op::RECORDS_SECRET`]'s `in`: the secret of one HOST-held credential, of a kind the calling
/// plugin's Statement declares it reads (an auth plugin's
/// [`FACT_READS_CREDENTIALS`](crate::abi::auth::FACT_READS_CREDENTIALS)); any other kind, or any
/// other caller, is REFUSED before anything is read. Span `0`'s value is the secret (SECRET material:
/// the plugin zeroes it when done) for ANY id: an unknown id answers a fixed dummy secret, in the
/// same time as a known one, so a reply never says whether the id exists. `value` =
/// [`SECRET_LIVE`] (the credential is live: its key enabled and not revoked) | [`SECRET_NOT_LIVE`]
/// (anything else, an unknown id included). May pend (a store-backed credential).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordsSecretIn {
    /// The head.
    pub head: ServiceHead,
    /// The credential kind (one the plugin declared).
    pub kind: AbiStr,
    /// The credential's id within its kind.
    pub id: AbiStr,
    /// Where the secret goes.
    pub into: ServiceBufs,
}

impl RecordsSecretIn {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `RecordsSecretIn { …, ..RecordsSecretIn::ZERO }` so a field appended
    /// later reads as not declared.
    pub const ZERO: Self = Self {
        head: ServiceHead::ZERO,
        kind: AbiStr::ZERO,
        id: AbiStr::ZERO,
        into: ServiceBufs::ZERO,
    };
}

/// `value` of [`op::RECORDS_SECRET`]: not live, or no such credential.
pub const SECRET_NOT_LIVE: u64 = 0;
/// `value` of [`op::RECORDS_SECRET`]: the credential is live.
pub const SECRET_LIVE: u64 = 1;

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
    /// [`DEST_RESOLVE`] | [`DEST_REFUSE_PRIVATE`] | [`DEST_EXPLAIN`].
    pub flags: u32,
    /// Appended: where the judged addresses go under [`DEST_RESOLVE`], one span each (key = the
    /// address as text, an IP literal without port or brackets; value absent). On
    /// [`DEST_ALLOWED`]: every address the judgement admitted, in the resolver's order, the first
    /// the one a dial pins. The set a plane hands back as `EstablishIn::within`, so the judge, its
    /// overlap check and the dial see one address set. On a refusal, nothing, unless
    /// [`DEST_EXPLAIN`] asks for what decided it. Without [`DEST_RESOLVE`] nothing is written.
    pub into: ServiceBufs,
}

/// [`DestJudgeIn::flags`]: resolve a name and judge every address it answers, and write the
/// addresses judged into [`DestJudgeIn::into`]; without it the judgement is the name's alone.
pub const DEST_RESOLVE: u32 = 1;
/// [`DestJudgeIn::flags`]: refuse every private address (and loopback name) under this judgement,
/// whatever the deployment's private-address setting and the class: the caller's own
/// configuration forbids the reach. The metadata refusal and the allow-list stand as they are.
pub const DEST_REFUSE_PRIVATE: u32 = 2;
/// [`DestJudgeIn::flags`], with [`DEST_RESOLVE`]: on a refusal an address or the resolution
/// decided, write ONE span into [`DestJudgeIn::into`] naming what decided it (key = the refused
/// address as text for [`DEST_INTERNAL`] / [`DEST_METADATA`]; the resolver's own reason for
/// [`DEST_UNRESOLVABLE`]; value absent). A refusal the name alone decided writes nothing.
pub const DEST_EXPLAIN: u32 = 4;

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
/// comes back whole: `value` = its status; span `0`'s value is its body (its key absent), and each
/// span after it one of its head fields (key = the name, value = the value), all over the bytes
/// written. Callable only inside a crossing that serves a unit; a call that serves none, nests past
/// the depth cap or finds no claim to serve it is REFUSED.
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

/// [`op::WORK_OPEN`]'s `in`: open a durable work handle for the calling unit's principal. `value` =
/// the handle; span `0`'s key is the handle's REFERENCE: [`WORK_REFERENCE_LEN`] lowercase hex digits
/// naming 128 random bits, the name the caller holds and hands [`op::WORK_FIND`]. A record longer
/// than [`MAX_WORK_RECORD`] is REFUSED; at the instance's bound of live handles the open is REFUSED
/// (a live handle is never evicted). Callable only inside a crossing that serves a unit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkOpenIn {
    /// The head.
    pub head: ServiceHead,
    /// The work kind (one of the record kinds the plugin declared).
    pub kind: AbiStr,
    /// The handle's record.
    pub record: Blob,
    /// Appended (ARCHITECT H3: the 128-bit reference): where the reference goes.
    pub into: ServiceBufs,
}

/// The length of a work handle's reference, in hex digits: 128 bits.
pub const WORK_REFERENCE_LEN: usize = 32;

/// The most bytes a work handle's record carries (the body lives in the plugin's own records; the
/// handle's record names it).
pub const MAX_WORK_RECORD: usize = 256;

/// [`op::WORK_FIND`]'s `in`: the scoped lookup, within the calling instance and the calling unit's
/// principal. Every denial (no such reference, another instance's, another principal's, a malformed
/// one) answers alike: READY [`ABSENT`], nothing written. Found, `value` = the handle, span `0`'s key
/// [`WORK_LIVE`] or [`WORK_SETTLED`] as one byte and its value the record.
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

/// `work.find`'s state byte: the handle is live.
pub const WORK_LIVE: u8 = 1;
/// `work.find`'s state byte: the handle is settled.
pub const WORK_SETTLED: u8 = 2;

/// [`op::WORK_SETTLE`]'s `in`: settle a live handle of the calling instance with its final record
/// (at most [`MAX_WORK_RECORD`] bytes). A settled handle is retained for the instance's retention
/// and then swept; settling one twice is REFUSED.
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

/// [`op::WORK_RESUME`]'s `in`: bind the handle's record to the calling unit, whose principal must be
/// the one the handle recorded. A continuation is a NEW unit, with its own arrival, admission and
/// window; this only binds the record: span `0`'s key is the state byte and its value the record.
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
/// `value` = a `TRUST_*` verdict. With [`TRUST_UNREACHABLE`] the plane reports it could not reach
/// the counterparty to look: the kernel answers its LAST verdict and changes nothing (the hash is
/// unread and may be empty), and the plane fails its call as an upstream failure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustSightIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// Its catalogue hash.
    pub catalogue_hash: AbiStr,
    /// [`TRUST_REACHED`] | [`TRUST_UNREACHABLE`]; any other value is a fault.
    pub outcome: u32,
    /// Alignment padding.
    pub _outcome_reserved: u32,
}

/// [`TrustSightIn::outcome`]: the plane reached the counterparty and reports what it serves.
pub const TRUST_REACHED: u32 = 0;
/// [`TrustSightIn::outcome`]: the plane could not reach the counterparty; nothing is sighted.
pub const TRUST_UNREACHABLE: u32 = 1;

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

/// [`op::TRUST_SIGHT_ITEM`]'s `in`: report the digest ONE ITEM of a counterparty (a tool, a skill:
/// the plane's own per-item trust key) is offered at now, from the plane's live re-fetch; the
/// kernel records it and answers a `TRUST_*` sighting verdict (`TRUST_NEW` the first sighting,
/// `TRUST_SAME` the same digest as the last, `TRUST_DRIFTED` another, `TRUST_QUARANTINED` when
/// the counterparty is). Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustSightItemIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// The item, opaque to the kernel.
    pub item: AbiStr,
    /// Its digest now, opaque to the kernel.
    pub digest: AbiStr,
}

/// [`op::TRUST_SERVES`]'s `in`: the KERNEL'S APPROVE as a query (ARCHITECT 2026-10-06: trust is
/// the kernel's Approve step), for a plane's route leg after its live re-fetch: whether the
/// counterparty serves `item` at `digest` (absent = the item's last sighting). `value` =
/// [`DISTRUST_NONE`] (it serves) or the `DISTRUST_*` that refuses it. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustServesIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// The item; absent = the counterparty as a whole.
    pub item: AbiStr,
    /// The digest it is offered at now; absent = its last sighting.
    pub digest: AbiStr,
}

/// THE ONE TRUST VOCABULARY (`trust.serves`'s value, and `abi::plane::RefusalIn::trust`): it serves.
pub const DISTRUST_NONE: u64 = 0;
/// The instance declares no such counterparty.
pub const DISTRUST_UNKNOWN: u64 = 1;
/// The counterparty was never sighted: nothing is pinned to judge by.
pub const DISTRUST_UNSIGHTED: u64 = 2;
/// The counterparty is quarantined: its last sighting drifted from its pin.
pub const DISTRUST_QUARANTINED: u64 = 3;
/// The item is known (sighted) and was never approved: a known item ungranted (a 403's case).
pub const DISTRUST_NOT_APPROVED: u64 = 4;
/// The item is offered at another digest than the one approved (or at none).
pub const DISTRUST_CHANGED: u64 = 5;
/// The item was never sighted at this counterparty: an unknown item (a 404's case).
pub const DISTRUST_UNKNOWN_ITEM: u64 = 6;

/// [`op::TRUST_DECIDE`]'s `in`: THE OPERATOR'S DECISION about one of the calling instance's trust
/// keys (the key `trust.sight_item` and `trust.serves` name: a counterparty, and optionally an item
/// there), made through the plane's own administrative verb: the ONE decide path the core-admin
/// `POST /api/v1/admin/trust/approve` and `/revoke` take, durable alike. An approval approves what
/// the caller SAW: `expected`, when stated, must be the key's current sighting. `value` = the
/// `TRUST_DECIDED_*` verdict after it, or the `UNDECIDED_*` that refused it. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustDecideIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// The item there; empty = the counterparty as a whole.
    pub item: AbiStr,
    /// The fingerprint (catalogue hash or item digest) the caller saw and approves; empty = none
    /// stated. Unread by a revoke.
    pub expected: AbiStr,
    /// [`TRUST_DECIDE_APPROVE`] | [`TRUST_DECIDE_REVOKE`]; any other value is a fault.
    pub decision: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`TrustDecideIn::decision`]: approve the key at what it was last sighted at.
pub const TRUST_DECIDE_APPROVE: u32 = 0;
/// [`TrustDecideIn::decision`]: revoke the key: refused until approved again.
pub const TRUST_DECIDE_REVOKE: u32 = 1;

/// `trust.decide`'s verdict: the key serves.
pub const TRUST_DECIDED_SERVING: u64 = 1;
/// `trust.decide`'s verdict: the key is not approved (new, or revoked): refused.
pub const TRUST_DECIDED_PENDING: u64 = 2;
/// `trust.decide`'s verdict: the key's sighting moved from its approval: refused until re-approved.
pub const TRUST_DECIDED_QUARANTINED: u64 = 3;
/// `trust.decide` refused: the key was never sighted at anything to approve.
pub const UNDECIDED_UNPINNED: u64 = 4;
/// `trust.decide` refused: the fingerprint the caller expects is not the key's current sighting.
pub const UNDECIDED_STALE: u64 = 5;
/// `trust.decide` refused: the calling instance has no such key.
pub const UNDECIDED_UNKNOWN: u64 = 6;
/// `trust.decide` refused: the counterparty declares no authenticity root; nothing at it is
/// approvable.
pub const UNDECIDED_ROOTLESS: u64 = 7;

/// [`op::TRUST_STATE`]'s `in`: the KERNEL'S TRUST STATE of one counterparty and its items, as the
/// core-admin `GET /api/v1/admin/trust` lists it, for a plane's own administrative views. `value` =
/// the counterparty's `KEY_*` state; one span per item, in item order: key = the item, value =
/// `<state word>\0<approved digest or empty>\0<last sighted digest or empty>`, the word one of
/// `new`, `same`, `drifted`, `quarantined`, `approved`. Short-buffer rule. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustStateIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty.
    pub counterparty: AbiStr,
    /// Where the items go.
    pub into: ServiceBufs,
}

/// `trust.state`'s value: sighted (or declared) and never approved, or revoked: refused.
pub const KEY_NEW: u64 = 1;
/// `trust.state`'s value: approved, and its last sighting is what was approved.
pub const KEY_SAME: u64 = 2;
/// `trust.state`'s value: approved, and its last sighting moved from it: refused until re-approved.
pub const KEY_DRIFTED: u64 = 3;
/// `trust.state`'s value: quarantined: refused until re-approved (or its pin is seen again).
pub const KEY_QUARANTINED: u64 = 4;
/// `trust.state`'s value: approved, and not sighted since.
pub const KEY_APPROVED: u64 = 5;

/// [`op::TRUST_VERIFY`]'s `in`: verify a document's detached signatures against the root key the
/// kernel holds for `counterparty` (the operator's out-of-band material its declared pin names).
/// The key selects the algorithm; a signature's header is only checked against it. `value` = a
/// `SIGNED_*` verdict; for [`SIGNED_ALGORITHM`] and [`SIGNED_CRITICAL`] the bytes written are the
/// algorithm or the critical member the signature named, with no span. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrustVerifyIn {
    /// The head.
    pub head: ServiceHead,
    /// The counterparty whose root key verifies.
    pub counterparty: AbiStr,
    /// The signed payload: exactly the bytes signed, before encoding.
    pub payload: Blob,
    /// The document's signatures as written: a JSON array of objects, each with `protected` and
    /// `signature`; empty = the document carries none.
    pub signatures: Blob,
    /// Where the refused algorithm or member goes.
    pub into: ServiceBufs,
}

/// `trust.verify` verdict: a signature verified against the root key.
pub const SIGNED_VERIFIED: u64 = 0;
/// `trust.verify` verdict: the document carries no signature.
pub const SIGNED_NONE: u64 = 1;
/// `trust.verify` verdict: more signatures than one document needs.
pub const SIGNED_TOO_MANY: u64 = 2;
/// `trust.verify` verdict: a protected header that is not an encoded object.
pub const SIGNED_MALFORMED_HEADER: u64 = 3;
/// `trust.verify` verdict: a header algorithm other than the root key's; the bytes name it.
pub const SIGNED_ALGORITHM: u64 = 4;
/// `trust.verify` verdict: a critical header member this verifier does not implement, named.
pub const SIGNED_CRITICAL: u64 = 5;
/// `trust.verify` verdict: a signature that is not one encoded signature of the key's size.
pub const SIGNED_MALFORMED_SIGNATURE: u64 = 6;
/// `trust.verify` verdict: well-formed, and no signature is the root key's.
pub const SIGNED_NOT_BY_ROOT: u64 = 7;
/// `trust.verify` verdict: the declared root key is not a key this verifier reads.
pub const SIGNED_MALFORMED_ROOT: u64 = 8;

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

/// [`op::ENTITLEMENT_CHECK`]'s target that asks whether the unit's PRINCIPAL STILL STANDS: the host
/// re-resolves it live (gone, disabled, expired, or a role binding withdrawn is not entitled). Every
/// other target is judged against the principal as re-resolved now, never the one admitted (a
/// long-lived response re-asks per frame, ARCHITECT round 4 Q-L3B-SURFACES (a)).
pub const ENTITLEMENT_STANDING: &str = "standing:";

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

/// [`op::HOOK_CALL`]'s `in` (THE DESIGN, host services; ARCHITECT H2 ruling: op 17): run the calling
/// unit's hook stage for an in-session sub-operation, over the hook kind's own
/// [`PromptView`](crate::abi::hook::PromptView). The hooks that run are the ones the CALLING UNIT
/// binds (its kernel-recorded plane and pool, never a field of the view), at the configuration
/// generation the unit was bound under, a resumed chain included. The host refuses an `in` that
/// breaks [`check_hook_call_in`]. `value`:
///
/// * [`HOOK_GATE`]: `0` = every gate passed; `400..=599` = a gate stopped it, that status, the
///   bytes its words;
/// * [`HOOK_REWRITE`], the chain from hook `from`: `0` = no hook from there on rewrote it;
///   `1 + i` = hook `i` rewrote it, the bytes the rewrite (`{"messages", "tools"}`, the document
///   `project`'s `rewrite` takes) — the plugin applies it and resumes with `from = 1 + i`;
///   `400..=599` = a hook stopped it, that status, the bytes its words.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookCallIn {
    /// The head.
    pub head: ServiceHead,
    /// [`HOOK_GATE`] | [`HOOK_REWRITE`].
    pub stage: u32,
    /// Where the rewrite chain resumes: the `value` the last call answered (`0` = its start), at
    /// most [`HOOK_FROM_MAX`]; `0` for a gate.
    pub from: u32,
    /// The view of the sub-operation's prompt.
    pub prompt: *const crate::abi::hook::PromptView,
    /// Where the reply goes.
    pub into: ServiceBufs,
}

/// `hook.call` stage: the calling unit's decision gates.
pub const HOOK_GATE: u32 = 0;
/// `hook.call` stage: the calling unit's rewrite chain.
pub const HOOK_REWRITE: u32 = 1;
/// The furthest a rewrite chain resumes (`HookCallIn::from`), and the most hooks one chain runs.
pub const HOOK_FROM_MAX: u32 = 255;
/// The least status a stopping hook answers `hook.call` with.
pub const HOOK_STOP_MIN: u64 = 400;
/// The greatest status a stopping hook answers `hook.call` with.
pub const HOOK_STOP_MAX: u64 = 599;

/// A `hook.call` `in`, before any hook runs: a known stage, a chain resumed no further than
/// [`HOOK_FROM_MAX`], a gate never resumed, and a prompt view. The host REFUSES an `in` that breaks
/// this, a distinct message per arm.
///
/// # Errors
///
/// [`Rule::UnknownCode`] for a stage that is neither; [`Rule::OverMax`] for `from` past
/// [`HOOK_FROM_MAX`]; [`Rule::Contradiction`] for a gate with a `from`; [`Rule::Missing`] for a NULL
/// prompt.
pub fn check_hook_call_in(i: &HookCallIn) -> Result<(), Fault> {
    if i.stage != HOOK_GATE && i.stage != HOOK_REWRITE {
        return Err(fault(Rule::UnknownCode, "hook_call.stage"));
    }
    if i.from > HOOK_FROM_MAX {
        return Err(fault(Rule::OverMax, "hook_call.from"));
    }
    if i.stage == HOOK_GATE && i.from != 0 {
        return Err(fault(Rule::Contradiction, "hook_call.from"));
    }
    if i.prompt.is_null() {
        return Err(fault(Rule::Missing, "hook_call.prompt"));
    }
    Ok(())
}

// ── snapshot ──────────────────────────────────────────────────────────────────────────────────

/// [`op::SNAPSHOT_READ`]'s `in`: THE HOST SNAPSHOT SERVICE (kind-neutral; `BUSBAR-1.6.0.md` owner
/// law 2026-09-27, "the data a plugin needs arrives through a kind-neutral host service, for example
/// a metrics snapshot service"). The host's metric families of `scope` ([`SNAPSHOT_SCOPE_WHOLE`] |
/// [`SNAPSHOT_SCOPE_HOOKS`]), laid out in the caller's `into.buf` in the export kind's scrape layout
/// ([`ScrapeFamily`](crate::abi::export::ScrapeFamily), its samples and their labels, every pointer
/// naming a range of that same buffer): READY with `value` = how many families, the
/// `ScrapeFamily` array at offset `0`, `len` the bytes the layout used; no spans. `into.buf` holds
/// [`SNAPSHOT_ALIGN`] alignment, or the call is FAULT.
///
/// FAILED with no `needed_*` = NOT READY (the host's recorder is not installed yet): the caller
/// answers "not ready, retry", never an empty success. A short buffer is FAILED with
/// `needed_bytes`, as every service. The scope is a kind-neutral argument, never a plugin's name.
/// The host lends the snapshot only to the crossing it granted it (the instance that serves its
/// well-known exposition routes); any other caller is REFUSED. Never pends: a ticketless re-call
/// after a short answer reads the snapshot again.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SnapshotReadIn {
    /// The head.
    pub head: ServiceHead,
    /// [`SNAPSHOT_SCOPE_WHOLE`] | [`SNAPSHOT_SCOPE_HOOKS`].
    pub scope: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Where the families are laid out (bytes only; `spans_cap` may be `0`).
    pub into: ServiceBufs,
}

/// [`SnapshotReadIn::scope`]: the host recorder's WHOLE snapshot, in its order (kind, then name),
/// read after the host refreshes its scrape-time gauges and folds every export instance's status.
pub const SNAPSHOT_SCOPE_WHOLE: u32 = 0;
/// [`SnapshotReadIn::scope`]: the families the configured hooks REPORT (each hook's own metrics,
/// labelled with its name), folded from the host's cache (it never waits on a hook).
pub const SNAPSHOT_SCOPE_HOOKS: u32 = 1;
/// How many scopes there are; a scope at or past it is REFUSED.
pub const SNAPSHOT_SCOPES: u32 = 2;
/// The alignment [`SnapshotReadIn::into`]'s `buf` holds (the scrape layout's: every record of it
/// is pointer-aligned).
pub const SNAPSHOT_ALIGN: usize = 8;

// ── need ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::NEED_ADMIT`]'s `in`: the host's verdict on the calling instance's declared need `need` (its
/// index in the Statement's needs), as the host admitted it when it bound the instance — its target,
/// its egress class, its trust anchors (a `trust_from` anchor that does not parse is refused). Never
/// pends. READY = admitted; REFUSED = not, with the host's text in `ServiceOut::error`.
///
/// It only lets a plugin's `open` answer its own words: the verdict binds FAIL-CLOSED regardless —
/// every establish on a need that failed admission is refused by the connector, whether or not the
/// plugin asked.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeedAdmitIn {
    /// The head.
    pub head: ServiceHead,
    /// The need, by its index in the Statement's needs.
    pub need: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

// ── disk ──────────────────────────────────────────────────────────────────────────────────────

/// [`op::DISK_APPEND`]'s `in`: append `bytes` to the local file the host maps the calling
/// instance's `dest_key` to (THE DESIGN, the host-owned bounded disk lane: the ONE exception to "no
/// blocking", scoped to the file export sink and the SQLite store; host service `disk.append`:
/// `{dest_key, bytes} -> {written, rotated}`, may pend, write-behind class).
///
/// The plugin names a destination KEY, never a path: the host maps the key to the path the
/// operator's configuration of the calling instance gives a destination its manifest declares, and
/// applies ROTATION itself, so no path and no rotation parameter comes from the plugin. The append
/// runs on the host's bounded disk lane: it may pend (the ticket is woken when the append is done),
/// and is callable only inside a ticketed op. On READY and on FAILED the host writes a
/// [`DiskWritten`] into `result`: what the rotation before this append did, and on READY the whole of
/// `bytes` landed.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DiskAppendIn {
    /// The head.
    pub head: ServiceHead,
    /// The destination key, one the calling instance's manifest declares.
    pub dest_key: AbiStr,
    /// The bytes to append, unchanged.
    pub bytes: Blob,
    /// Where the host writes the result.
    pub result: *mut DiskWritten,
}

/// `disk.append`'s result, written by the host into [`DiskAppendIn::result`] on READY and FAILED.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskWritten {
    /// `size_of::<DiskWritten>()`.
    pub size: u32,
    /// [`DISK_ROTATED`] when the host rotated the file (renamed it to its first archive) before
    /// this append, else `0`.
    pub rotated: u8,
    /// The steps of that rotation that failed: [`DISK_RETENTION_FAILED`] | [`DISK_SHIFT_FAILED`] |
    /// [`DISK_RENAME_FAILED`]; `0` = none (or no rotation ran).
    pub faults: u8,
    /// Alignment padding.
    pub _reserved: [u8; 2],
    /// The bytes appended: `bytes.len` on READY, `0` otherwise.
    pub written: u64,
}

impl DiskWritten {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `DiskWritten { …, ..DiskWritten::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        size: 0,
        rotated: 0,
        faults: 0,
        _reserved: [0; 2],
        written: 0,
    };
}

/// [`DiskWritten::rotated`]: the host rotated the file before appending.
pub const DISK_ROTATED: u8 = 1;
/// [`DiskWritten::faults`]: dropping the oldest archive failed (the archive series may exceed the
/// host's retention).
pub const DISK_RETENTION_FAILED: u8 = 1;
/// [`DiskWritten::faults`]: shifting an archive up one slot failed (it was left in place).
pub const DISK_SHIFT_FAILED: u8 = 2;
/// [`DiskWritten::faults`]: renaming the live file to its first archive failed (the append went to
/// the live file, which keeps growing; nothing was truncated).
pub const DISK_RENAME_FAILED: u8 = 4;
/// Every [`DiskWritten::faults`] bit.
pub const DISK_FAULTS: u8 = DISK_RETENTION_FAILED | DISK_SHIFT_FAILED | DISK_RENAME_FAILED;
/// A FAILED `disk.append`'s `ServiceOut::value`: the file could not be opened for the append.
pub const DISK_OPEN_FAILED: u64 = 1;
/// A FAILED `disk.append`'s `ServiceOut::value`: the file opened, and writing the bytes failed.
pub const DISK_APPEND_FAILED: u64 = 2;

// ── carrier sessions ──────────────────────────────────────────────────────────────────────────

/// The head field a CARRIER SESSION's arrivals carry, naming the session they arrived over: the
/// root states it on every unit it opens from a session that holds one carrier open (a process's
/// own stdin/stdout), and never lets a caller state it. Its value is the session's number, in
/// decimal; a plugin hands that number back to [`op::SESSION_EMIT`].
pub const CARRIER_SESSION_FIELD: &str = "busbar-carrier-session";

/// [`op::SESSION_EMIT`]'s `in`: write `bytes`, UNSOLICITED, on the open carrier session `session`
/// (its number, as [`CARRIER_SESSION_FIELD`] named it), outside any unit: a notification, a request
/// of the plugin's own, a keepalive. Unbilled; the host attributes it to the session's verified
/// principal and audits it as a session event. A session that is not open, or not the calling
/// instance's, is REFUSED. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionEmitIn {
    /// The head.
    pub head: ServiceHead,
    /// The session.
    pub session: u64,
    /// The bytes, written as they are.
    pub bytes: Blob,
}

/// `session.emit`'s `in`: a session is named (never `0`) and something is written.
///
/// # Errors
///
/// [`Rule::Missing`] for no session or no bytes.
pub const fn check_session_emit_in(i: &SessionEmitIn) -> Result<(), Fault> {
    if i.session == 0 {
        return Err(fault(Rule::Missing, "session_emit.session"));
    }
    if i.bytes.len == 0 {
        return Err(fault(Rule::Missing, "session_emit.bytes"));
    }
    Ok(())
}

// ── the host auth handle ──────────────────────────────────────────────────────────────────────

/// One auth handle a transport presents: an inbound guest-list line's or an outbound binding's.
///
/// THE HOST AUTH HANDLE (THE DESIGN, Auth points and guest lists, items 3 to 7; the plugin ABI's
/// "auth is on the memory ABI"): a transport calls its bound auth only at its auth points, only
/// through the host, with [`op::AUTH_CALL`]; the kernel makes the call and no plugin calls another.
/// One type both ways: the ref of an inbound line (handed to an accepting transport in its line
/// table) and the ref of an outbound binding are the same shape and cross the same service.
///
/// `mac` is the kernel's keyed MAC over (owner, configuration generation, `id`) under the kernel's
/// key (#74). A ref is OWNER-SCOPED (#65): a transport may present only the refs of its own
/// listener's lines or its own binding, at the generation they were minted under. Every service
/// that takes one verifies it FIRST and REFUSES a ref of another owner, of another generation, or
/// with a `mac` the kernel did not mint, before any other work. `id == 0` names no handle.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRef {
    /// The line or binding the kernel minted it for.
    pub id: u64,
    /// The kernel's MAC over (owner, generation, `id`).
    pub mac: u64,
}

impl AuthRef {
    /// No handle.
    pub const NONE: Self = Self { id: 0, mac: 0 };

    /// Whether this names no handle.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.id == 0
    }
}

/// One request's unit, as the kernel binds it at the ABI (#74): minted on the request's first
/// crossing, verified on every later one.
///
/// The kernel mints it on the request's first [`op::AUTH_CALL`] (or at [`op::UNIT_HAND_IN`] for a
/// line whose auth is `none`), before any verdict, and the transport hands it back on every later
/// crossing of that request. `mac` is the kernel's keyed MAC over (the request's own kernel secret,
/// generation, owner, line, `id`): a unit replayed from another request, presented by another owner
/// or for another line is REFUSED. All zero ([`UnitRef::NONE`]) = no unit yet.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitRef {
    /// The unit.
    pub id: u64,
    /// The kernel's MAC over (request secret, generation, owner, line, `id`).
    pub mac: u64,
}

impl UnitRef {
    /// No unit yet.
    pub const NONE: Self = Self { id: 0, mac: 0 };

    /// Whether this names no unit.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.id == 0
    }
}

/// The request a transport decoded, as the auth handle and the kernel read it: neutral fields only.
///
/// Borrowed for the call. Absent where the call is made at the peer point (no request yet).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HeadView {
    /// The method.
    pub method: AbiStr,
    /// The target's path, as received (never normalized).
    pub target: AbiStr,
    /// The authority (host\[:port\]).
    pub authority: AbiStr,
    /// The query without `?`, as received; absent = none.
    pub query: AbiStr,
    /// The head's field lines, in order, as received.
    pub fields: *const Field,
    /// How many, at most [`MAX_SPANS`].
    pub fields_len: usize,
    /// THE UPSTREAM'S SCHEME, as a code (`SCHEME_*`): [`SCHEME_SECURE`] when the stream rides the
    /// connector's connection security, [`SCHEME_PLAIN`] when it rides in the clear. The HOST
    /// declares it, from the route's upstream URL; a transport never derives it from its own dial
    /// (connection security is the connector's alone).
    /// [`SCHEME_UNDECLARED`] (`0`, a zeroed view) is REFUSED off the peer point
    /// ([`SCHEME_UNDECLARED_REFUSED`]): a zero never grants, and is never read as plain. A tail
    /// addition (pre-tag v1).
    pub scheme: u8,
    /// Alignment padding; zero.
    pub _scheme_reserved: [u8; 7],
}

/// [`HeadView::scheme`]: not declared. Refused off the peer point; never read as plain.
pub const SCHEME_UNDECLARED: u8 = 0;
/// [`HeadView::scheme`]: the upstream is reached in the clear.
pub const SCHEME_PLAIN: u8 = 1;
/// [`HeadView::scheme`]: the upstream is reached over the connector's connection security.
pub const SCHEME_SECURE: u8 = 2;

/// THE REFUSAL of an `auth.call` whose request view declares no scheme ([`SCHEME_UNDECLARED`]):
/// the host's answer text, REFUSED, before the auth runs.
pub const SCHEME_UNDECLARED_REFUSED: &str = "the request view declares no scheme";

/// [`AuthAnswer::flow`]: the transport carries on with the request.
pub const FLOW_CONTINUE: u32 = 0;
/// [`AuthAnswer::flow`]: the transport stops the request and asks [`op::UNIT_REFUSE`] for the answer.
pub const FLOW_STOP: u32 = 1;

/// What [`op::AUTH_CALL`] and [`op::UNIT_HAND_IN`] answer beyond [`ServiceOut`].
///
/// At the peer point it is the whole answer: continue or stop, with no field, name or byte beside
/// it.
///
/// Written by the host into the caller's `answer` on READY, and only then; the caller's check
/// ([`check_auth_call`], [`check_unit_hand_in`]) refuses one of another size. The pattern
/// `disk.append` uses for a result wider than [`ServiceOut`]: the bytes and spans written are
/// `ServiceOut::len` and `ServiceOut::items`, a short buffer its `needed_*`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthAnswer {
    /// `size_of::<AuthAnswer>()`, exactly.
    pub size: u32,
    /// [`FLOW_CONTINUE`] | [`FLOW_STOP`].
    pub flow: u32,
    /// The request's unit: minted on its first call, the same one on every later call; none at the
    /// peer point.
    pub unit: UnitRef,
}

/// [`op::AUTH_CALL`]'s `in`: call the auth `auth` names, at `point`, through the host.
///
/// May pend (an auth's call may be not-ready with a wake): callable only inside a ticketed op, and
/// a pending call parks only its own stream. The host verifies `auth` (and a non-zero `unit`)
/// before anything else, and refuses an `in` that breaks [`check_auth_call_in`] or is not exactly
/// this size.
///
/// AN INBOUND LINE'S REF. The kernel calls, in list order, each of the line's undecided auths that
/// needs `point`, and answers the transport ONLY continue or stop ([`AuthAnswer::flow`]) plus the
/// names it must strip: one [`FieldSpan`] per credential field line ([`FIELD_SENSITIVE`]) or query
/// key ([`FIELD_QUERY`]), its `name` a span into `buf` and its `value` absent. The VERDICT and the
/// verified CREDENTIAL go to the kernel first-hand and never appear in the answer.
///
/// THE PEER POINT. At `POINT_PEER` (once per connection, before any head: a dialling framer makes
/// it at `begin` when its binding's points hold it) the answer is ONLY continue or stop: no field,
/// no name and no byte, on either side. Outbound, the peer point never carries key material: the
/// client identity of a secured connection stays the connector's. An answer at the peer point that
/// writes any byte or span is refused ([`check_auth_call`]).
///
/// AN OUTBOUND BINDING'S REF. The same call answers the auth fields that join the head, each a
/// [`FieldSpan`] with its name and value spans into `buf` and its flags the auth's
/// ([`FIELD_SENSITIVE`], [`FIELD_QUERY`]); the transport adds them, replacing any field of the same
/// name, and adds nothing to the head after. `buf` then holds credential material: the transport
/// never logs it and zeroises it once the head is encoded.
///
/// A short buffer is FAILED with `needed_bytes` / `needed_items` at their full sizes, nothing
/// written, and the one re-call on the same handle reads the stored answer.
///
/// [`FieldSpan`]: crate::abi::auth::FieldSpan
/// [`FIELD_SENSITIVE`]: crate::abi::auth::FIELD_SENSITIVE
/// [`FIELD_QUERY`]: crate::abi::auth::FIELD_QUERY
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthCallIn {
    /// The head.
    pub head: ServiceHead,
    /// The line's or the binding's handle.
    pub auth: AuthRef,
    /// The request's unit; [`UnitRef::NONE`] on the request's first call and at the peer point.
    pub unit: UnitRef,
    /// The [`AuthPoint`](crate::abi::auth::AuthPoint) bit this call is made at: exactly one of
    /// `POINT_PEER`, `POINT_HEAD`, `POINT_HEAD_BODY`.
    pub point: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// The request; absent at the peer point.
    pub request: HeadView,
    /// The whole body; present only at `POINT_HEAD_BODY`, at most the line's `body_limit`.
    pub body: Blob,
    /// The caller's bytes the answer's names (and outbound values) are written into.
    pub buf: *mut u8,
    /// Their capacity.
    pub cap: usize,
    /// The caller's spans, one per name.
    pub spans: *mut FieldSpan,
    /// Their capacity, in spans.
    pub spans_cap: usize,
    /// Where the host writes the [`AuthAnswer`].
    pub answer: *mut AuthAnswer,
}

/// [`UnitHandInIn::line`] and [`UnitRefuseIn::line`]: no line matched.
pub const LINE_NONE: u32 = u32::MAX;

/// [`op::UNIT_HAND_IN`]'s `in`: hand the request in with the line the transport matched.
///
/// Never pends. Before any plane receives the request the kernel checks, and answers
/// [`FLOW_STOP`] on any failure: (a) the line is on the calling listener's list and is the line
/// the list's own match gives for the request's method, target and matched fields; (b) unless the
/// line's auth is `none`, the kernel holds a verdict for this unit that came first-hand from that
/// line's auth, through the handle bound to it (a line with auth and no verdict is refused); (c)
/// none of the names that auth named is still present. For a `none` line `unit` is
/// [`UnitRef::NONE`] and the kernel mints the unit here. On [`FLOW_STOP`] the transport asks
/// [`op::UNIT_REFUSE`] for the answer. The host verifies `auth` and a non-zero `unit` first.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitHandInIn {
    /// The head.
    pub head: ServiceHead,
    /// The matched line's handle.
    pub auth: AuthRef,
    /// The request's unit; [`UnitRef::NONE`] for a `none` line.
    pub unit: UnitRef,
    /// The matched line.
    pub line: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// The request, after the transport stripped what the auth named.
    pub request: HeadView,
    /// Where the host writes the [`AuthAnswer`].
    pub answer: *mut AuthAnswer,
}

/// [`UnitRefuseIn::cause`]: the request matched no line.
pub const REFUSE_NO_ROUTE: u32 = 1;
/// [`UnitRefuseIn::cause`]: a line's path and fields matched and no line admits the method.
pub const REFUSE_METHOD_MISS: u32 = 2;
/// [`UnitRefuseIn::cause`]: the body passed the line's `body_limit`, before any verdict.
pub const REFUSE_OVER_GATE: u32 = 3;
/// [`UnitRefuseIn::cause`]: an auth call answered [`FLOW_STOP`].
pub const REFUSE_STOPPED: u32 = 4;
/// [`UnitRefuseIn::cause`]: [`op::UNIT_HAND_IN`] answered [`FLOW_STOP`].
pub const REFUSE_CHECK_FAILED: u32 = 5;

/// What [`op::UNIT_REFUSE`] answers: the refusal the transport frames verbatim.
///
/// Written by the host into the caller's `answer` on READY. Its fields and body are KERNEL-OWNED,
/// valid until the next call on that connection; the transport copies or frames them before then,
/// and writes no refusal bytes of its own.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RefusalAnswer {
    /// `size_of::<RefusalAnswer>()`, exactly.
    pub size: u32,
    /// The status, `100..=599`.
    pub status: u16,
    /// Alignment padding.
    pub _reserved: u16,
    /// The answer's head fields, in order.
    pub fields: *const Field,
    /// How many, at most [`MAX_SPANS`].
    pub fields_len: usize,
    /// The answer's body.
    pub body: Blob,
}

/// [`op::UNIT_REFUSE`]'s `in`: ask the kernel for the refusal of a request, which it owns and audits.
///
/// Never pends. The bytes come from the line's claimant under the line's refusal dialect or, with
/// no line, from the listener's default. The host verifies a non-zero `unit` first and refuses an
/// `in` that breaks [`check_unit_refuse_in`] or is not exactly this size.
///
/// `request` is the request being refused, as the transport decoded it. A refusal with no unit (no
/// route, a method miss, a body over the gate before any verdict) is answered with the listener's
/// 1.5.5 bytes, and those are shaped by the request's method and target (THE DESIGN, the inbound
/// refusal answers, item 4, "the listener's 1.5.5 default"), so the kernel reads them here and
/// nowhere else.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitRefuseIn {
    /// The head.
    pub head: ServiceHead,
    /// The request's unit; [`UnitRef::NONE`] when it has none (no line, or refused before any).
    pub unit: UnitRef,
    /// `REFUSE_*`.
    pub cause: u32,
    /// The matched line; [`LINE_NONE`] for [`REFUSE_NO_ROUTE`], and only then.
    pub line: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// Where the host writes the [`RefusalAnswer`].
    pub answer: *mut RefusalAnswer,
    /// The request being refused, as decoded (a tail addition, pre-tag v1). Its `scheme` is the
    /// one the transport states for the connection.
    pub request: HeadView,
}

/// A [`HeadView`]: no string or list is a count behind NULL, and at most [`MAX_SPANS`] fields.
///
/// # Errors
///
/// [`Rule::NullWithCount`]; [`Rule::OverMax`] for too many fields.
pub fn check_head_view(v: &HeadView) -> Result<(), Fault> {
    check::text(v.method, "head_view.method")?;
    check::text(v.target, "head_view.target")?;
    check::text(v.authority, "head_view.authority")?;
    check::text(v.query, "head_view.query")?;
    if v.scheme > SCHEME_SECURE {
        return Err(fault(Rule::UnknownCode, "head_view.scheme"));
    }
    if v._scheme_reserved != [0; 7] {
        return Err(fault(Rule::UnknownCode, "head_view._scheme_reserved"));
    }
    check::listed(v.fields, v.fields_len, "head_view.fields")?;
    if v.fields_len as u64 > MAX_SPANS {
        return Err(fault(Rule::OverMax, "head_view.fields"));
    }
    Ok(())
}

/// The host's check of an `auth.call` `in`, after its exact size ([`check_head_exact`]): a handle,
/// exactly one known point, a body only at the body point, no unit at the peer point, well-formed
/// lists and an answer slot.
///
/// # Errors
///
/// [`Rule::Missing`] for no handle, no answer slot, or a request view that declares no scheme
/// ([`SCHEME_UNDECLARED`]) off the peer point; [`Rule::UnknownCode`] for a point that is not
/// exactly one of the three; [`Rule::Contradiction`] for a body off the body point or a unit at
/// the peer point; [`Rule::NullWithCount`] for a count behind NULL.
pub fn check_auth_call_in(i: &AuthCallIn) -> Result<(), Fault> {
    use crate::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
    if i.auth.is_none() {
        return Err(fault(Rule::Missing, "auth_call.auth"));
    }
    if !matches!(i.point, POINT_PEER | POINT_HEAD | POINT_HEAD_BODY) {
        return Err(fault(Rule::UnknownCode, "auth_call.point"));
    }
    check::listed(i.body.ptr, i.body.len, "auth_call.body")?;
    if i.point != POINT_HEAD_BODY && (i.body.len != 0 || !i.body.ptr.is_null()) {
        return Err(fault(Rule::Contradiction, "auth_call.body"));
    }
    if i.point == POINT_PEER && !i.unit.is_none() {
        return Err(fault(Rule::Contradiction, "auth_call.unit"));
    }
    check_head_view(&i.request)?;
    // A request's scheme is the host's to declare; an undeclared one (a zeroed view) never grants.
    if i.point != POINT_PEER && i.request.scheme == SCHEME_UNDECLARED {
        return Err(fault(Rule::Missing, "head_view.scheme"));
    }
    check::listed(i.buf.cast_const(), i.cap, "auth_call.buf")?;
    check::listed(i.spans.cast_const(), i.spans_cap, "auth_call.spans")?;
    if i.answer.is_null() {
        return Err(fault(Rule::Missing, "auth_call.answer"));
    }
    Ok(())
}

/// The host's check of a `unit.hand_in` `in`, after its exact size: a handle, a line, a request
/// with a method, and an answer slot.
///
/// # Errors
///
/// [`Rule::Missing`] for no handle, no line, no method or no answer slot; [`Rule::NullWithCount`]
/// and [`Rule::OverMax`] by [`check_head_view`].
pub fn check_unit_hand_in_in(i: &UnitHandInIn) -> Result<(), Fault> {
    if i.auth.is_none() {
        return Err(fault(Rule::Missing, "unit_hand_in.auth"));
    }
    if i.line == LINE_NONE {
        return Err(fault(Rule::Missing, "unit_hand_in.line"));
    }
    check_head_view(&i.request)?;
    if i.request.method.len == 0 {
        return Err(fault(Rule::Missing, "unit_hand_in.request.method"));
    }
    if i.answer.is_null() {
        return Err(fault(Rule::Missing, "unit_hand_in.answer"));
    }
    Ok(())
}

/// The host's check of a `unit.refuse` `in`, after its exact size: a known cause, [`LINE_NONE`]
/// exactly for [`REFUSE_NO_ROUTE`], no unit without a line, an answer slot, and the request being
/// refused ([`check_head_view`], with its method named).
///
/// # Errors
///
/// [`Rule::UnknownCode`] for an unknown cause; [`Rule::Contradiction`] for a line that disagrees
/// with the cause or a unit with no line; [`Rule::Missing`] for no answer slot or no request
/// method; the [`check_head_view`] faults for a malformed request.
pub fn check_unit_refuse_in(i: &UnitRefuseIn) -> Result<(), Fault> {
    if i.cause < REFUSE_NO_ROUTE || i.cause > REFUSE_CHECK_FAILED {
        return Err(fault(Rule::UnknownCode, "unit_refuse.cause"));
    }
    if (i.cause == REFUSE_NO_ROUTE) != (i.line == LINE_NONE) {
        return Err(fault(Rule::Contradiction, "unit_refuse.line"));
    }
    if i.line == LINE_NONE && !i.unit.is_none() {
        return Err(fault(Rule::Contradiction, "unit_refuse.unit"));
    }
    if i.answer.is_null() {
        return Err(fault(Rule::Missing, "unit_refuse.answer"));
    }
    check_head_view(&i.request)?;
    if i.request.method.len == 0 {
        return Err(fault(Rule::Missing, "unit_refuse.request.method"));
    }
    Ok(())
}

// ── tickets ───────────────────────────────────────────────────────────────────────────────────

/// The most record bytes one `ticket.mint` stores with its ticket.
pub const MAX_TICKET_RECORD: u64 = 64 * 1024;

/// [`op::TICKET_MINT`]'s `in`: mint a TICKET, a short-lived single-use credential, for the principal
/// of the unit the calling crossing serves, and store `record` with it. The host mints it through
/// its own token stamp under the mint ceiling (a lifetime above the ceiling is clamped to it),
/// prefixed with the plugin's declared issued-id prefix, and binds it to the audience only a
/// [`CLAIM_TICKET`](crate::abi::plane::CLAIM_TICKET) claim's gate verifies. READY: the ticket
/// credential in the bytes written (no span), `value` = its expiry in Unix seconds. A crossing that
/// serves no unit, a unit with no principal, or a plugin that declares no issued-id prefix is
/// REFUSED. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TicketMintIn {
    /// The head.
    pub head: ServiceHead,
    /// The lifetime asked, in seconds.
    pub ttl_secs: u64,
    /// The bytes stored with the ticket and handed back once by [`op::TICKET_TAKE`].
    pub record: Blob,
    /// Where the ticket goes.
    pub into: ServiceBufs,
}

/// `ticket.mint`'s `in`, before anything is minted: a lifetime of at least one second, and a record
/// within [`MAX_TICKET_RECORD`]. The host REFUSES an `in` that breaks this.
///
/// # Errors
///
/// [`Rule::Missing`] for `ttl_secs == 0`; [`Rule::OverMax`] for a record above
/// [`MAX_TICKET_RECORD`].
pub const fn check_ticket_mint_in(i: &TicketMintIn) -> Result<(), Fault> {
    if i.ttl_secs == 0 {
        return Err(fault(Rule::Missing, "ticket_mint.ttl_secs"));
    }
    if i.record.len as u64 > MAX_TICKET_RECORD {
        return Err(fault(Rule::OverMax, "ticket_mint.record"));
    }
    Ok(())
}

/// `ticket.take`: the unit was admitted by a key, not a ticket; nothing is written.
pub const TICKET_NONE: u64 = 0;
/// `ticket.take`: the record of the ticket that admitted the unit, written once.
pub const TICKET_TAKEN: u64 = 1;

/// [`op::TICKET_TAKE`]'s `in`: the record stored with the ticket that admitted the unit the calling
/// crossing serves. The gate consumed the ticket when it admitted the unit; the record is handed
/// back ONCE. READY [`TICKET_TAKEN`] with the record in the bytes written (no span), or
/// [`TICKET_NONE`] with nothing written when a key admitted the unit. A crossing that serves no
/// unit, or a second take for one unit, is REFUSED. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TicketTakeIn {
    /// The head.
    pub head: ServiceHead,
    /// Where the record goes.
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
    /// [`op::NEED_ADMIT`], in [`NeedAdmitIn`].
    pub need_admit: Option<ServiceFn>,
    /// [`op::TRUST_VERIFY`], in [`TrustVerifyIn`].
    pub trust_verify: Option<ServiceFn>,
    /// [`op::RECORDS_SECRET`], in [`RecordsSecretIn`].
    pub records_secret: Option<ServiceFn>,
    /// [`op::DISK_APPEND`], in [`DiskAppendIn`].
    pub disk_append: Option<ServiceFn>,
    /// [`op::SNAPSHOT_READ`], in [`SnapshotReadIn`].
    pub snapshot_read: Option<ServiceFn>,
    /// [`op::TRUST_SIGHT_ITEM`], in [`TrustSightItemIn`]. A tail addition.
    pub trust_sight_item: Option<ServiceFn>,
    /// [`op::TRUST_SERVES`], in [`TrustServesIn`]. A tail addition.
    pub trust_serves: Option<ServiceFn>,
    /// [`op::TRUST_DECIDE`], in [`TrustDecideIn`]. A tail addition.
    pub trust_decide: Option<ServiceFn>,
    /// [`op::TRUST_STATE`], in [`TrustStateIn`]. A tail addition.
    pub trust_state: Option<ServiceFn>,
    /// [`op::SESSION_EMIT`], in [`SessionEmitIn`].
    pub session_emit: Option<ServiceFn>,
    /// [`op::AUTH_CALL`], in [`AuthCallIn`].
    pub auth_call: Option<ServiceFn>,
    /// [`op::UNIT_HAND_IN`], in [`UnitHandInIn`].
    pub unit_hand_in: Option<ServiceFn>,
    /// [`op::UNIT_REFUSE`], in [`UnitRefuseIn`].
    pub unit_refuse: Option<ServiceFn>,
    /// [`op::TICKET_MINT`], in [`TicketMintIn`]. A tail addition.
    pub ticket_mint: Option<ServiceFn>,
    /// [`op::TICKET_TAKE`], in [`TicketTakeIn`]. A tail addition.
    pub ticket_take: Option<ServiceFn>,
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

/// The head of an `in` whose size is EXACT: the op is the slot's and the stated size is the `in`
/// type's, neither more nor less. Every service whose `in` has one v1 size checks this, never
/// [`check_head`]'s "at least".
///
/// # Errors
///
/// [`Rule::Contradiction`] for another op; [`Rule::Foreign`] for any other size.
pub const fn check_head_exact(
    head: &ServiceHead,
    service: u32,
    in_size: usize,
) -> Result<(), Fault> {
    if head.op != service {
        return Err(fault(Rule::Contradiction, "service.head.op"));
    }
    if head.size as usize != in_size {
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

/// The host's check of a `disk.append` `in`: a key is named, neither the key nor the bytes come as a
/// count behind NULL, the bytes fit one answer's bound, and there is a result slot.
///
/// # Errors
///
/// [`Rule::NullWithCount`]; [`Rule::Missing`] for an absent key or result slot; [`Rule::OverMax`]
/// for bytes over [`MAX_BYTES`].
pub fn check_disk_append_in(i: &DiskAppendIn) -> Result<(), Fault> {
    check::text(i.dest_key, "disk_append.dest_key")?;
    if i.dest_key.len == 0 {
        return Err(fault(Rule::Missing, "disk_append.dest_key"));
    }
    check::listed(i.bytes.ptr, i.bytes.len, "disk_append.bytes")?;
    if i.bytes.len as u64 > MAX_BYTES {
        return Err(fault(Rule::OverMax, "disk_append.bytes"));
    }
    if i.result.is_null() {
        return Err(fault(Rule::Missing, "disk_append.result"));
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
    let (cap, spans_cap) = shape
        .into
        .map_or((0, 0), |b| (b.cap as u64, b.spans_cap as u64));
    let filled = common(
        ret,
        head,
        out,
        shape.may_pend,
        shape.values,
        (cap, spans_cap),
    )?;
    if ret.outcome() == Outcome::Ready {
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

/// [`answer`]'s rules short of reading any span: the outcome, the size, PENDING, the short-buffer
/// rule over `caps` (bytes, spans) and a READY `value` in `values`.
fn common(
    ret: RawOutcome,
    head: &ServiceHead,
    out: &ServiceOut,
    may_pend: bool,
    values: (u64, u64),
    (cap, spans_cap): (u64, u64),
) -> Result<Filled, Fault> {
    let outcome = ret.outcome();
    if out.outcome.outcome() != outcome {
        return Err(fault(Rule::Contradiction, "service.out.outcome"));
    }
    if out.size as usize != core::mem::size_of::<ServiceOut>() {
        return Err(fault(Rule::Foreign, "service.out.size"));
    }
    if outcome == Outcome::Pending && (!may_pend || head.handle.ticket.is_none()) {
        return Err(fault(Rule::Contradiction, "service.out.pending"));
    }
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
        check::code(out.value, values.0, values.1, "service.out.value")?;
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

/// `records.secret`'s answer.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_records_secret(
    i: &RecordsSecretIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        into(op::RECORDS_SECRET, i.into, (SECRET_NOT_LIVE, SECRET_LIVE)),
    )
}

/// `snapshot.read`'s answer: the common rules; READY writes no spans.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_snapshot_read(
    i: &SnapshotReadIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let bytes_only = ServiceBufs {
        spans: core::ptr::null_mut(),
        spans_cap: 0,
        ..i.into
    };
    answer(ret, &i.head, out, into(op::SNAPSHOT_READ, bytes_only, ANY))
}

/// A `snapshot.read` `in`: a known scope, and a buffer of the scrape layout's alignment.
///
/// # Errors
///
/// [`Rule::UnknownCode`] for an unknown scope; [`Rule::Foreign`] for a misaligned buffer.
pub fn check_snapshot_read_in(i: &SnapshotReadIn) -> Result<(), Fault> {
    if i.scope >= SNAPSHOT_SCOPES {
        return Err(fault(Rule::UnknownCode, "snapshot_read.scope"));
    }
    if !i.into.buf.is_null() && !(i.into.buf as usize).is_multiple_of(SNAPSHOT_ALIGN) {
        return Err(fault(Rule::Foreign, "snapshot_read.into.buf"));
    }
    Ok(())
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
        into(op::DEST_JUDGE, i.into, (DEST_ALLOWED, DEST_NO_ADDRESSES)),
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
    let filled = answer(
        ret,
        &i.head,
        out,
        into(op::WORK_OPEN, i.into, (1, u64::MAX)),
    )?;
    if ret.outcome() == Outcome::Ready && out.items != 1 {
        return Err(fault(Rule::Contradiction, "work_open.out.items"));
    }
    Ok(filled)
}

/// A `work.open` or `work.settle` record: at most [`MAX_WORK_RECORD`] bytes. The host REFUSES an
/// `in` that breaks this, before anything is opened or settled.
///
/// # Errors
///
/// [`Rule::OverMax`].
pub const fn check_work_record(record: &Blob) -> Result<(), Fault> {
    if record.len > MAX_WORK_RECORD {
        return Err(fault(Rule::OverMax, "work.record"));
    }
    Ok(())
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

/// `trust.sight_item`'s answer: a sighting verdict.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_sight_item(
    i: &TrustSightItemIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::TRUST_SIGHT_ITEM, (TRUST_NEW, TRUST_QUARANTINED)),
    )
}

/// `trust.serves`'s answer: [`DISTRUST_NONE`] or a `DISTRUST_*`.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_serves(
    i: &TrustServesIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(op::TRUST_SERVES, (DISTRUST_NONE, DISTRUST_UNKNOWN_ITEM)),
    )
}

/// `trust.decide`'s answer: a `TRUST_DECIDED_*` verdict or an `UNDECIDED_*`.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_decide(
    i: &TrustDecideIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        bare(
            op::TRUST_DECIDE,
            (TRUST_DECIDED_SERVING, UNDECIDED_ROOTLESS),
        ),
    )
}

/// `trust.state`'s answer: a `KEY_*` state, and the items into the caller's buffers.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_state(
    i: &TrustStateIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(
        ret,
        &i.head,
        out,
        into(op::TRUST_STATE, i.into, (KEY_NEW, KEY_APPROVED)),
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

/// `hook.call`'s answer: the common rules, and on READY `0`, a stopping status
/// ([`HOOK_STOP_MIN`]`..=`[`HOOK_STOP_MAX`]), or, for [`HOOK_REWRITE`] only, the `1 + i` of a
/// rewriting hook within [`HOOK_FROM_MAX`].
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_hook_call(i: &HookCallIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    let filled = answer(
        ret,
        &i.head,
        out,
        into(op::HOOK_CALL, i.into, (0, HOOK_STOP_MAX)),
    )?;
    // READY answers `0`, a stopping status, or (a rewrite chain only) `1 + i` within the cap.
    if ret.outcome() == Outcome::Ready && out.value != 0 && out.value < HOOK_STOP_MIN {
        let resumable = i.stage == HOOK_REWRITE && out.value <= u64::from(HOOK_FROM_MAX);
        if !resumable {
            return Err(fault(Rule::UnknownCode, "hook_call.out.value"));
        }
    }
    Ok(filled)
}

/// `need.admit`'s answer: never pends; READY (`value` 0) = admitted, REFUSED = not, with the
/// host's text.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_need_admit(
    i: &NeedAdmitIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, bare(op::NEED_ADMIT, (0, 0)))
}

/// `session.emit`'s answer: the common rules, nothing written back.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_session_emit(
    i: &SessionEmitIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    answer(ret, &i.head, out, bare(op::SESSION_EMIT, (0, 0)))
}

/// `ticket.mint`'s answer: the common rules, and on READY a ticket written (at least one byte, no
/// span) and an expiry after the epoch.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_ticket_mint(
    i: &TicketMintIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(
        ret,
        &i.head,
        out,
        into(op::TICKET_MINT, i.into, (1, u64::MAX)),
    )?;
    if ret.outcome() == Outcome::Ready && (out.len == 0 || out.items != 0) {
        return Err(fault(Rule::Contradiction, "ticket_mint.out.len"));
    }
    Ok(filled)
}

/// `ticket.take`'s answer: the common rules, and on READY no span, and bytes only with
/// [`TICKET_TAKEN`].
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_ticket_take(
    i: &TicketTakeIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(
        ret,
        &i.head,
        out,
        into(op::TICKET_TAKE, i.into, (TICKET_NONE, TICKET_TAKEN)),
    )?;
    if ret.outcome() == Outcome::Ready
        && (out.items != 0 || (out.value == TICKET_NONE && out.len != 0))
    {
        return Err(fault(Rule::Contradiction, "ticket_take.out.len"));
    }
    Ok(filled)
}

/// `trust.verify`'s answer: the common rules, and on READY no span, and bytes only with the two
/// verdicts that name what they refused.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_trust_verify(
    i: &TrustVerifyIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(
        ret,
        &i.head,
        out,
        into(
            op::TRUST_VERIFY,
            i.into,
            (SIGNED_VERIFIED, SIGNED_MALFORMED_ROOT),
        ),
    )?;
    let names = matches!(out.value, SIGNED_ALGORITHM | SIGNED_CRITICAL);
    if ret.outcome() == Outcome::Ready && (out.items != 0 || (out.len != 0 && !names)) {
        return Err(fault(Rule::Contradiction, "trust_verify.out.len"));
    }
    Ok(filled)
}

/// `disk.append`'s answer: the common rules; on READY or FAILED a [`DiskWritten`] of this layout's
/// size, `rotated` a known value and `faults` known bits; on READY `written` the WHOLE of `bytes` (an
/// append lands whole or answers otherwise); on FAILED `written` `0` and `value` one of
/// [`DISK_OPEN_FAILED`] / [`DISK_APPEND_FAILED`].
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_disk_append(
    i: &DiskAppendIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(ret, &i.head, out, bare(op::DISK_APPEND, (0, 0)))?;
    let outcome = ret.outcome();
    if !matches!(outcome, Outcome::Ready | Outcome::Failed) {
        return Ok(filled);
    }
    if outcome == Outcome::Failed {
        check::code(
            out.value,
            DISK_OPEN_FAILED,
            DISK_APPEND_FAILED,
            "disk_append.out.value",
        )?;
    }
    if i.result.is_null() {
        return Err(fault(Rule::NullWithCount, "disk_append.result"));
    }
    // SAFETY: the caller's own result slot, checked non-NULL.
    let w = unsafe { core::ptr::read_unaligned(i.result) };
    if w.size as usize != core::mem::size_of::<DiskWritten>() {
        return Err(fault(Rule::Foreign, "disk_append.result.size"));
    }
    check::code(
        u64::from(w.rotated),
        0,
        u64::from(DISK_ROTATED),
        "disk_append.result.rotated",
    )?;
    check::bits(
        u64::from(w.faults),
        u64::from(DISK_FAULTS),
        "disk_append.result.faults",
    )?;
    let whole = if outcome == Outcome::Ready {
        i.bytes.len as u64
    } else {
        0
    };
    if w.written != whole {
        return Err(fault(Rule::Contradiction, "disk_append.result.written"));
    }
    Ok(filled)
}

/// The answer slot an `in` named, read whole: present, and exactly `T`'s size by its leading `u32`.
///
/// # Safety
///
/// A non-NULL `p` is the caller's own slot of a `T`.
unsafe fn exact_answer<T: Copy>(p: *mut T, field: &'static str) -> Result<T, Fault> {
    if p.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    // SAFETY: the caller's own slot of a `T`, checked non-NULL; its leading `u32` is its size.
    let size = unsafe { p.cast::<u32>().read_unaligned() };
    if size as usize != core::mem::size_of::<T>() {
        return Err(fault(Rule::Foreign, field));
    }
    // SAFETY: as above.
    Ok(unsafe { p.read_unaligned() })
}

/// The unit an [`AuthAnswer`] carries, against the one the call presented: none at the peer
/// point; otherwise present, and the presented one when one was presented.
fn check_answer_unit(
    sent: UnitRef,
    got: UnitRef,
    peer: bool,
    field: &'static str,
) -> Result<(), Fault> {
    if peer {
        if !got.is_none() {
            return Err(fault(Rule::Contradiction, field));
        }
        return Ok(());
    }
    if got.is_none() {
        return Err(fault(Rule::Missing, field));
    }
    if !sent.is_none() && sent != got {
        return Err(fault(Rule::Contradiction, field));
    }
    Ok(())
}

/// `auth.call`'s answer: the common rules over the caller's `buf`/`spans` (the short-buffer rule
/// included; `value` is `0`), and on READY an [`AuthAnswer`] of this layout's size with a known
/// flow and the request's unit, at most `spans_cap` spans, each with a present name and a value
/// absent or inside the bytes written, its flags only `FIELD_SENSITIVE` and `FIELD_QUERY`. At the
/// peer point the answer writes no byte and no span: it is continue or stop and nothing else.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_auth_call(i: &AuthCallIn, ret: RawOutcome, out: &ServiceOut) -> Result<Filled, Fault> {
    use crate::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE, POINT_PEER};
    let filled = common(
        ret,
        &i.head,
        out,
        may_pend(op::AUTH_CALL),
        (0, 0),
        (i.cap as u64, i.spans_cap as u64),
    )?;
    if ret.outcome() != Outcome::Ready {
        return Ok(filled);
    }
    // SAFETY: the caller's own answer slot.
    let a = unsafe { exact_answer(i.answer, "auth_call.answer") }?;
    check::code(
        u64::from(a.flow),
        u64::from(FLOW_CONTINUE),
        u64::from(FLOW_STOP),
        "auth_call.answer.flow",
    )?;
    check_answer_unit(
        i.unit,
        a.unit,
        i.point == POINT_PEER,
        "auth_call.answer.unit",
    )?;
    // THE PEER POINT ANSWERS ONLY CONTINUE OR STOP: no field, no name, no byte (an outbound
    // binding's peer call never carries key material; the client identity stays the
    // connector's).
    if i.point == POINT_PEER && (out.len != 0 || out.items != 0) {
        return Err(fault(Rule::Contradiction, "auth_call.answer.peer_fields"));
    }
    // SAFETY: the caller's own spans buffer, `spans_cap` long; `reported` checks the count against
    // it before building the slice.
    let spans = unsafe {
        check::reported(
            i.spans.cast_const(),
            out.items,
            i.spans_cap as u64,
            "auth_call.out.items",
        )
    }?;
    for s in spans {
        if s.name.offset == check::SPAN_ABSENT {
            return Err(fault(Rule::Missing, "auth_call.span.name"));
        }
        check::span(s.name.offset, s.name.len, out.len, "auth_call.span.name")?;
        check::span(s.value.offset, s.value.len, out.len, "auth_call.span.value")?;
        check::bits(
            u64::from(s.flags),
            u64::from(FIELD_SENSITIVE | FIELD_QUERY),
            "auth_call.span.flags",
        )?;
    }
    Ok(filled)
}

/// `unit.hand_in`'s answer: the common rules (no buffer; `value` is `0`), and on READY an
/// [`AuthAnswer`] of this layout's size with a known flow and the request's unit (the presented
/// one, or the one minted for a `none` line).
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_unit_hand_in(
    i: &UnitHandInIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(ret, &i.head, out, bare(op::UNIT_HAND_IN, (0, 0)))?;
    if ret.outcome() != Outcome::Ready {
        return Ok(filled);
    }
    // SAFETY: the caller's own answer slot.
    let a = unsafe { exact_answer(i.answer, "unit_hand_in.answer") }?;
    check::code(
        u64::from(a.flow),
        u64::from(FLOW_CONTINUE),
        u64::from(FLOW_STOP),
        "unit_hand_in.answer.flow",
    )?;
    check_answer_unit(i.unit, a.unit, false, "unit_hand_in.answer.unit")?;
    Ok(filled)
}

/// `unit.refuse`'s answer: the common rules (no buffer; `value` is `0`), and on READY a
/// [`RefusalAnswer`] of this layout's size with a status in `100..=599`, at most [`MAX_SPANS`]
/// fields and no list or body a count behind NULL.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_unit_refuse(
    i: &UnitRefuseIn,
    ret: RawOutcome,
    out: &ServiceOut,
) -> Result<Filled, Fault> {
    let filled = answer(ret, &i.head, out, bare(op::UNIT_REFUSE, (0, 0)))?;
    if ret.outcome() != Outcome::Ready {
        return Ok(filled);
    }
    // SAFETY: the caller's own answer slot.
    let a = unsafe { exact_answer(i.answer, "unit_refuse.answer") }?;
    check::code(u64::from(a.status), 100, 599, "unit_refuse.answer.status")?;
    check::listed(a.fields, a.fields_len, "unit_refuse.answer.fields")?;
    if a.fields_len as u64 > MAX_SPANS {
        return Err(fault(Rule::OverMax, "unit_refuse.answer.fields"));
    }
    check::listed(a.body.ptr, a.body.len, "unit_refuse.answer.body")?;
    Ok(filled)
}

#[cfg(test)]
#[path = "../tests/host_service_tests.rs"]
mod tests;
