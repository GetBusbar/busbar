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
//! THE KEPT-CYCLE RULE. On a driver ticket, a `tick` of a kept cycle (something was held at the
//! tick's start) starts new work. It never re-issues a handle issued earlier in the cycle; the
//! `drive` the pending service's wake brings resumes it. Such a re-issue is FAULT, and nothing runs.
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

use std::os::raw::c_void;

use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome, Span};
use crate::abi::mechanism::check::{self, fault, Dim, Fault, Filled, Rule, MAX_BYTES};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx};

/// A host service: `svc(ctx, in, out)`. `extern "C"`: a panic escaping it aborts.
///
/// # Safety
///
/// The selected slot determines the input layout. Every input range it reads must be live and
/// initialized, and every output range it writes exclusively writable for its stated capacity,
/// including nested pointers. The frame and `out` must cover the prefixes their size fields
/// advertise (capped at the slot's current layout). Keep those ranges valid for the invocation
/// and follow the slot's pending protocol. NULL or short prefixes are allowed only where the slot
/// explicitly rejects them before access. Use the SDK's borrowed wrappers for safe calls.
///
/// ```compile_fail,E0133
/// use busbar_contract::abi::{host::service::*, mechanism::ticket::HostCtx};
/// fn call(f: ServiceFn, ctx: HostCtx, input: *const core::ffi::c_void, out: *mut ServiceOut) {
///     let _ = f(ctx, input, out);
/// }
/// ```
pub type ServiceFn =
    unsafe extern "C" fn(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome;

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
    pub const ZERO: Self = Self {
        size: 0,
        op: 0,
        handle: CompletionHandle::ZERO,
    };
}

/// Every service's `out`, in either table. The caller states its `size`; the host writes
/// `min(size, its own)` bytes of it (`write_out`), and refuses an `out` below
/// `SERVICE_OUT_V1` before the service runs (`lent_out`), so an `out` may grow by appending
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

impl ServiceOut {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
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
    /// `content.scan`.
    pub const CONTENT_SCAN: u32 = 15;
    /// `hook.call`.
    pub const HOOK_CALL: u32 = 16;
    /// `random.fill`.
    pub const RANDOM_FILL: u32 = 17;
    /// `need.admit`.
    pub const NEED_ADMIT: u32 = 18;
    /// `trust.verify`.
    pub const TRUST_VERIFY: u32 = 19;
    /// `records.secret`.
    pub const RECORDS_SECRET: u32 = 20;
    /// `disk.append`.
    pub const DISK_APPEND: u32 = 21;
    /// `snapshot.read`.
    pub const SNAPSHOT_READ: u32 = 22;
    /// `trust.sight_item`.
    pub const TRUST_SIGHT_ITEM: u32 = 23;
    /// `trust.serves`.
    pub const TRUST_SERVES: u32 = 24;
    /// `trust.decide`.
    pub const TRUST_DECIDE: u32 = 25;
    /// `trust.state`.
    pub const TRUST_STATE: u32 = 26;
    /// `session.emit`.
    pub const SESSION_EMIT: u32 = 27;
    /// `auth.call`.
    pub const AUTH_CALL: u32 = 28;
    /// `unit.hand_in`.
    pub const UNIT_HAND_IN: u32 = 29;
    /// `unit.refuse`.
    pub const UNIT_REFUSE: u32 = 30;
    /// `ticket.mint`.
    pub const TICKET_MINT: u32 = 31;
    /// `ticket.take`.
    pub const TICKET_TAKE: u32 = 32;
    /// `work.status`: instance-scoped, read-only durable receipt status.
    pub const WORK_STATUS: u32 = 33;
    /// `outbound.authorize`: publish, bind, revoke or prepare scoped outbound custody.
    pub const OUTBOUND_AUTHORIZE: u32 = 34;
    /// Invocation-scoped, configured hook child dispatch.
    pub const HOOK_CHILD: u32 = 35;
    /// `directory.get` ([`super::directory`]).
    pub const DIRECTORY_GET: u32 = 36;
    /// `directory.lookup`.
    pub const DIRECTORY_LOOKUP: u32 = 37;
    /// `directory.scan`.
    pub const DIRECTORY_SCAN: u32 = 38;
    /// `directory.count`.
    pub const DIRECTORY_COUNT: u32 = 39;
    /// `directory.create`.
    pub const DIRECTORY_CREATE: u32 = 40;
    /// `directory.apply`.
    pub const DIRECTORY_APPLY: u32 = 41;
    /// `directory.delete`.
    pub const DIRECTORY_DELETE: u32 = 42;
    /// `migrate.admit`: whether the boot can seal a store's recoverable 1.5.5 credentials.
    pub const MIGRATE_ADMIT: u32 = 43;
}

/// How many services [`HostSlots`] holds.
pub const SERVICES: u32 = 44;

/// Whether a service may answer PENDING, and so is callable only inside a ticketed op. `false` for a service that always answers at once.
#[must_use]
pub const fn may_pend(service: u32) -> bool {
    !matches!(
        service,
        op::CLOCK_NOW
            | op::SIGN
            | op::TRUST_DUE
            | op::VERIFY_STORE
            | op::RANDOM_FILL
            | op::NEED_ADMIT
            | op::TRUST_VERIFY
            | op::TRUST_SERVES
            | op::TRUST_STATE
            | op::SESSION_EMIT
            | op::UNIT_HAND_IN
            | op::UNIT_REFUSE
            | op::TICKET_TAKE
            | op::MIGRATE_ADMIT
    ) && service < SERVICES
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
/// `value` of ANY service's REFUSED answer: the host backs the service for no caller here, so it is
/// read as UNSERVED, exactly as an absent slot (the `records.*` services on a deployment with no
/// store bound). Every other REFUSED `value` is a refusal, and an older host's REFUSED (`0`) stays
/// one: the reading only ever narrows to "unserved" on the host's word, never by default. A host
/// answers it only once the caller's own standing (admission, declared kind, a well-formed `in`) is
/// judged, so a misconfigured caller is REFUSED, never UNSERVED.
pub const REFUSED_UNSERVED: u64 = u64::MAX;

/// [`DestJudgeIn::flags`]: resolve a name and judge every address it answers, and write the
pub const DEST_RESOLVE: u32 = 1;
/// [`DestJudgeIn::flags`]: refuse every private address (and loopback name) under this judgement,
pub const DEST_REFUSE_PRIVATE: u32 = 2;
/// [`DestJudgeIn::flags`], with [`DEST_RESOLVE`]: on a refusal an address or the resolution
pub const DEST_EXPLAIN: u32 = 4;
/// [`DestJudgeIn::flags`] (appended in 1.6.0): judge only THE PLAINTEXT RULE for `dest`, the
/// destination a plugin is about to reach WITHOUT TLS (a `postgres://` URL with
/// `sslmode=disable`, a `redis://` URL, an `ldap://` URL without StartTLS): [`DEST_ALLOWED`] when
/// it is loopback (a loopback literal or `localhost`) or an exact `advanced.tls.destinations` entry
/// admits plaintext to it, else [`DEST_PLAINTEXT`]. The class and the other flags are not read; the
/// destination itself is judged again at the dial. A plugin refuses its setting on
/// [`DEST_PLAINTEXT`] (BUSBAR-3141). A host from before this flag answers FAULT (an unknown flag
/// bit), so a plugin that needs the answer pins a core that has it.
pub const DEST_PLAINTEXT_INTENT: u32 = 8;

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

/// The length of a work handle's reference, in hex digits: 128 bits.
pub const WORK_REFERENCE_LEN: usize = 32;

/// The most bytes a work handle's record carries (the body lives in the plugin's own records; the
pub const MAX_WORK_RECORD: usize = 256;

/// `work.find`'s state byte: the handle is live.
pub const WORK_LIVE: u8 = 1;
/// `work.find`'s state byte: the handle is settled.
pub const WORK_SETTLED: u8 = 2;

/// No retained work in the calling instance's namespace; never settlement proof.
pub const WORK_STATUS_ABSENT: u64 = 0;
/// The owned work is live.
pub const WORK_STATUS_LIVE: u64 = 1;
/// The owned work has a confirmed durable settlement.
pub const WORK_STATUS_SETTLED: u64 = 2;
/// A settlement write is in flight and not yet confirmed.
pub const WORK_STATUS_SETTLING: u64 = 3;

/// `trust.sight` verdict: never seen before.
pub const TRUST_NEW: u64 = 1;
/// `trust.sight` verdict: the pinned catalogue.
pub const TRUST_SAME: u64 = 2;
/// `trust.sight` verdict: the catalogue moved from its pin.
pub const TRUST_DRIFTED: u64 = 3;
/// `trust.sight` verdict: the counterparty is quarantined.
pub const TRUST_QUARANTINED: u64 = 4;

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
pub const UNDECIDED_ROOTLESS: u64 = 7;

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

/// `verify.lookup`: a cached entry.
pub const VERIFY_HIT: u64 = 1;
/// `verify.lookup`: the caller leads.
pub const VERIFY_LEAD: u64 = 2;
/// `verify.lookup`: the caller followed a leader, whose entry is in span `0`.
pub const VERIFY_FOLLOW: u64 = 3;

/// The most bytes one `random.fill` answers.
pub const MAX_RANDOM_FILL: u64 = 1024;

/// `content.scan`: the content passes.
pub const CONTENT_PASS: u64 = 0;
/// `content.scan`: the gate blocked it.
pub const CONTENT_BLOCK: u64 = 1;

/// Failed snapshot reads with this value mean the recorder is not installed yet.
/// Other Failed outcomes retain their failure meaning.
pub const SNAPSHOT_NOT_READY_VALUE: u64 = 1;

/// [`SnapshotReadIn::scope`]: the host recorder's WHOLE snapshot, in its order (kind, then name),
pub const SNAPSHOT_SCOPE_WHOLE: u32 = 0;
/// [`SnapshotReadIn::scope`]: the families the configured hooks REPORT (each hook's own metrics,
pub const SNAPSHOT_SCOPE_HOOKS: u32 = 1;

/// [`DiskWritten::faults`]: dropping the oldest archive failed (the archive series may exceed the
pub const DISK_RETENTION_FAILED: u8 = 1;
/// [`DiskWritten::faults`]: shifting an archive up one slot failed (it was left in place).
pub const DISK_SHIFT_FAILED: u8 = 2;
/// [`DiskWritten::faults`]: renaming the live file to its first archive failed (the append went to
pub const DISK_RENAME_FAILED: u8 = 4;
/// A FAILED `disk.append`'s `ServiceOut::value`: the file could not be opened for the append.
pub const DISK_OPEN_FAILED: u64 = 1;
/// A FAILED `disk.append`'s `ServiceOut::value`: the file opened, and writing the bytes failed.
pub const DISK_APPEND_FAILED: u64 = 2;

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

/// [`HeadView::scheme`]: not declared. Refused off the peer point; never read as plain.
pub const SCHEME_UNDECLARED: u8 = 0;

/// [`AuthAnswer::flow`]: the transport carries on with the request.
pub const FLOW_CONTINUE: u32 = 0;
/// [`AuthAnswer::flow`]: the transport stops the request and asks [`op::UNIT_REFUSE`] for the answer.
pub const FLOW_STOP: u32 = 1;

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

/// The most record bytes one `ticket.mint` stores with its ticket.
pub const MAX_TICKET_RECORD: u64 = 64 * 1024;

/// `ticket.take`: the unit was admitted by a key, not a ticket; nothing is written.
pub const TICKET_NONE: u64 = 0;
/// `ticket.take`: the record of the ticket that admitted the unit, written once.
pub const TICKET_TAKEN: u64 = 1;

/// A REFUSED `ticket.mint`'s code: no ticket is minted, for a reason the reason text gives.
pub const TICKET_REFUSED_OTHER: u32 = 0;
/// A REFUSED `ticket.mint`'s code: the principal's key holds its maximum of unredeemed tickets.
pub const KEY_SATURATED: u32 = 1;
/// A REFUSED `ticket.mint`'s code: this node holds its maximum of unredeemed tickets.
pub const NODE_SATURATED: u32 = 2;

/// A REFUSED `ticket.mint`'s `ServiceOut::value`: its refusal `code` ([`TICKET_REFUSED_OTHER`],
/// [`KEY_SATURATED`], [`NODE_SATURATED`]) in the high 32 bits, and the seconds after which a retry
/// may find a free slot (`0` = none stated) in the low 32. [`TicketRefused::of`] reads it back.
#[must_use]
pub const fn ticket_refused(code: u32, retry_after_secs: u32) -> u64 {
    ((code as u64) << 32) | retry_after_secs as u64
}

/// A REFUSED `ticket.mint`'s value, read back ([`ticket_refused`]'s inverse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketRefused {
    /// The refusal code: [`TICKET_REFUSED_OTHER`], [`KEY_SATURATED`] or [`NODE_SATURATED`].
    pub code: u32,
    /// The seconds after which a retry may find a free slot; `0` = none stated.
    pub retry_after_secs: u32,
}

impl TicketRefused {
    /// The refusal `value` carries.
    #[must_use]
    pub const fn of(value: u64) -> Self {
        Self {
            code: (value >> 32) as u32,
            retry_after_secs: value as u32,
        }
    }
}

/// Publish or replace host-held outbound credential custody.
pub const OUTBOUND_PUBLISH: u32 = 1;
/// Bind an existing custody revision to the serving unit.
pub const OUTBOUND_BIND: u32 = 2;
/// Revoke custody, including a revision-zero tombstone for an absent connection.
pub const OUTBOUND_REVOKE: u32 = 3;
/// Prepare a sealed request body for one governed dispatch by the serving unit.
pub const OUTBOUND_PREPARE: u32 = 4;
/// Publish a reusable sealed request body in host-held connection custody.
pub const OUTBOUND_PUBLISH_BODY: u32 = 5;

/// THE HOST SERVICES TABLE: one [`ServiceFn`] per [`op`], in index order. A NULL slot is a service
/// this host does not offer, and a plugin that needs it refuses to open.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostSlots {
    /// `size_of::<HostSlots>()`.
    pub size: u32,
    /// [`SERVICES`].
    pub slots: u32,
    /// [`op::CLOCK_NOW`], in `ClockNowIn`.
    pub clock_now: Option<ServiceFn>,
    /// [`op::RECORDS_GET`], in `RecordsGetIn`.
    pub records_get: Option<ServiceFn>,
    /// [`op::RECORDS_LIST`], in `RecordsListIn`.
    pub records_list: Option<ServiceFn>,
    /// [`op::RECORDS_CLAIM`], in `RecordsClaimIn`.
    pub records_claim: Option<ServiceFn>,
    /// [`op::DEST_JUDGE`], in `DestJudgeIn`.
    pub dest_judge: Option<ServiceFn>,
    /// [`op::SIGN`], in `SignIn`.
    pub sign: Option<ServiceFn>,
    /// [`op::UNIT_NEST`], in `UnitNestIn`.
    pub unit_nest: Option<ServiceFn>,
    /// [`op::WORK_OPEN`], in `WorkOpenIn`.
    pub work_open: Option<ServiceFn>,
    /// [`op::WORK_FIND`], in `WorkFindIn`.
    pub work_find: Option<ServiceFn>,
    /// [`op::WORK_SETTLE`], in `WorkSettleIn`.
    pub work_settle: Option<ServiceFn>,
    /// [`op::WORK_RESUME`], in `WorkResumeIn`.
    pub work_resume: Option<ServiceFn>,
    /// [`op::TRUST_SIGHT`], in `TrustSightIn`.
    pub trust_sight: Option<ServiceFn>,
    /// [`op::TRUST_DUE`], in `TrustDueIn`.
    pub trust_due: Option<ServiceFn>,
    /// [`op::VERIFY_LOOKUP`], in `VerifyLookupIn`.
    pub verify_lookup: Option<ServiceFn>,
    /// [`op::VERIFY_STORE`], in `VerifyStoreIn`.
    pub verify_store: Option<ServiceFn>,
    /// [`op::CONTENT_SCAN`], in `ContentScanIn`.
    pub content_scan: Option<ServiceFn>,
    /// [`op::HOOK_CALL`], in `HookCallIn`.
    pub hook_call: Option<ServiceFn>,
    /// [`op::RANDOM_FILL`], in `RandomFillIn`.
    pub random_fill: Option<ServiceFn>,
    /// [`op::NEED_ADMIT`], in `NeedAdmitIn`.
    pub need_admit: Option<ServiceFn>,
    /// [`op::TRUST_VERIFY`], in `TrustVerifyIn`.
    pub trust_verify: Option<ServiceFn>,
    /// [`op::RECORDS_SECRET`], in `RecordsSecretIn`.
    pub records_secret: Option<ServiceFn>,
    /// [`op::DISK_APPEND`], in `DiskAppendIn`.
    pub disk_append: Option<ServiceFn>,
    /// [`op::SNAPSHOT_READ`], in `SnapshotReadIn`.
    pub snapshot_read: Option<ServiceFn>,
    /// [`op::TRUST_SIGHT_ITEM`], in `TrustSightItemIn`. A tail addition.
    pub trust_sight_item: Option<ServiceFn>,
    /// [`op::TRUST_SERVES`], in `TrustServesIn`. A tail addition.
    pub trust_serves: Option<ServiceFn>,
    /// [`op::TRUST_DECIDE`], in `TrustDecideIn`. A tail addition.
    pub trust_decide: Option<ServiceFn>,
    /// [`op::TRUST_STATE`], in `TrustStateIn`. A tail addition.
    pub trust_state: Option<ServiceFn>,
    /// [`op::SESSION_EMIT`], in `SessionEmitIn`.
    pub session_emit: Option<ServiceFn>,
    /// [`op::AUTH_CALL`], in `AuthCallIn`.
    pub auth_call: Option<ServiceFn>,
    /// [`op::UNIT_HAND_IN`], in `UnitHandInIn`.
    pub unit_hand_in: Option<ServiceFn>,
    /// [`op::UNIT_REFUSE`], in `UnitRefuseIn`.
    pub unit_refuse: Option<ServiceFn>,
    /// [`op::TICKET_MINT`], in `TicketMintIn`. A tail addition.
    pub ticket_mint: Option<ServiceFn>,
    /// [`op::TICKET_TAKE`], in `TicketTakeIn`. A tail addition.
    pub ticket_take: Option<ServiceFn>,
    /// [`op::WORK_STATUS`], in `WorkStatusIn`. Optional size-checked tail addition.
    pub work_status: Option<ServiceFn>,
    /// [`op::OUTBOUND_AUTHORIZE`]. Optional size-checked tail addition.
    pub outbound_authorize: Option<ServiceFn>,
    /// [`op::HOOK_CHILD`], optional size-checked tail.
    pub hook_child: Option<ServiceFn>,
    /// [`op::DIRECTORY_GET`], in `super::directory::DirectoryGetIn`. A tail addition (1.6.0).
    pub directory_get: Option<ServiceFn>,
    /// [`op::DIRECTORY_LOOKUP`], in `super::directory::DirectoryLookupIn`. A tail addition.
    pub directory_lookup: Option<ServiceFn>,
    /// [`op::DIRECTORY_SCAN`], in `super::directory::DirectoryScanIn`. A tail addition.
    pub directory_scan: Option<ServiceFn>,
    /// [`op::DIRECTORY_COUNT`], in `super::directory::DirectoryCountIn`. A tail addition.
    pub directory_count: Option<ServiceFn>,
    /// [`op::DIRECTORY_CREATE`], in `super::directory::DirectoryCreateIn`. A tail addition.
    pub directory_create: Option<ServiceFn>,
    /// [`op::DIRECTORY_APPLY`], in `super::directory::DirectoryApplyIn`. A tail addition.
    pub directory_apply: Option<ServiceFn>,
    /// [`op::DIRECTORY_DELETE`], in `super::directory::DirectoryDeleteIn`. A tail addition.
    pub directory_delete: Option<ServiceFn>,
    /// [`op::MIGRATE_ADMIT`], in `MigrateAdmitIn`. A tail addition (MIGRATE-ON-BOOT r34).
    pub migrate_admit: Option<ServiceFn>,
}

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
///
/// # Safety
///
/// If READY reports a nonzero in-cap span count, `shape.into` must name that many aligned,
/// initialized `ItemSpan`s, readable without concurrent writes. NULL is rejected before reading.
unsafe fn answer(
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
