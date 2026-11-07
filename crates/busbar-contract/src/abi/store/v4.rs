// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive Store wire contract, using ABI 3 after the released 1.5.5 ABI 2.
//! Transitional business tables use a different layout and are not interchangeable.
//!
//! Every nested input span is borrowed, immutable, and retained with its call/ticket.
//! Output descriptors and bytes are host-owned; no payload lease is introduced.
//! Counts and checked aggregate allocation sizes use the host admission budget, not
//! the plane's 512-byte record limit or its conditional extension's 16-MiB ceiling.
//! COMMIT short-buffer recovery retains and resubmits the exact candidate and id;
//! it never replans or remints an id to obtain the original result.
//! COMMIT uses FAILED for an unknown transport outcome and REFUSED for a definitive
//! no-effect rejection; neither is a READY commit verdict. A later failure does not
//! resolve any earlier unknown send.
//! This module declares shapes only; it does not enable backend admission/execution.

use super::HostBuf;
use crate::abi::mechanism::call::{Blob, DeadlineClass, InHead, Op, OutHead};
use crate::abi::mechanism::check::OpContract;
use crate::abi::mechanism::decl::abi_struct;
use crate::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use crate::abi::mechanism::ticket::HostTables;

/// Primitive Store ABI: one increment from the version 2 released with v1.5.5.
/// Admission also requires this table's independent layout fingerprint.
pub const ABI_VERSION: u32 = 3;
/// Initial canonical candidate encoding version.
pub const CODEC_VERSION: u32 = 1;
/// Mandatory primitive slots after the existing lifecycle.
pub const KIND_SLOTS: u32 = 5;
/// Lifecycle and primitive slots together.
pub const TABLE_SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// Mandatory slot indices, in table order.
pub mod slot {
    use super::LIFECYCLE_SLOTS;
    /// Coherent exact-address read.
    pub const READ: u32 = LIFECYCLE_SLOTS;
    /// Ordered namespace page.
    pub const SCAN: u32 = LIFECYCLE_SLOTS + 1;
    /// Atomic candidate and receipt.
    pub const COMMIT: u32 = LIFECYCLE_SLOTS + 2;
    /// Authoritative UTC observation.
    pub const CLOCK: u32 = LIFECYCLE_SLOTS + 3;
    /// Retained native pre-open inspection and upgrade session.
    pub const BOOTSTRAP: u32 = LIFECYCLE_SLOTS + 4;
}

abi_struct! {
    /// Raw bytes; NULL is permitted only at zero length.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Bytes {
        /// First byte; no text or NUL interpretation.
        pub ptr: *const u8,
        /// Byte length.
        pub len: usize,
    }

    /// Opaque logical address, ordered by raw key bytes.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Address {
        /// Core-assigned namespace identity.
        pub namespace: [u8; 16],
        /// Exact raw key; also used as a prefix by DeleteRange.
        pub key: Bytes,
    }

    /// Optional serialization-time UTC interval in Unix seconds.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct TimeGuard {
        /// TIME_NOT_BEFORE and/or TIME_BEFORE; zero means unguarded.
        pub flags: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Inclusive lower bound when flagged; zero otherwise.
        pub not_before: u64,
        /// Exclusive upper bound when flagged; zero otherwise.
        pub before: u64,
    }

    /// Immutable replay authority; never derived from wall time.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct AttemptId {
        /// Target dataset identity.
        pub dataset: [u8; 16],
        /// Registered writer identity, never reused.
        pub writer: [u8; 16],
        /// Operation identity within that writer.
        pub operation: [u8; 16],
        /// Dataset writer epoch.
        pub writer_epoch: u64,
        /// Registered execution epoch; receipts precede fence checks.
        pub execution_epoch: u64,
    }

    /// Pre-mutation absence or exact-byte comparison.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Predicate {
        /// Compared address; duplicates are refused.
        pub address: Address,
        /// PREDICATE_ABSENT or PREDICATE_EXACT.
        pub tag: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Exact expected octets; absent tag requires an empty blob.
        pub expected: Blob,
    }

    /// Explicit Put/Delete/DeleteRange; empty bytes never imply deletion.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Mutation {
        /// Point address, or raw namespace/prefix for DeleteRange.
        pub address: Address,
        /// MUTATION_PUT, MUTATION_DELETE or MUTATION_DELETE_RANGE.
        pub tag: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// DeleteRange matches only this exact key length; zero for point operations.
        pub exact_length: u64,
        /// Put octets; delete tags require an empty blob.
        pub value: Blob,
    }

    /// Immutable candidate with fixed framing separate from payload accounting.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Candidate {
        /// Exact replay identity.
        pub id: AttemptId,
        /// Canonical candidate encoding version.
        pub codec: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Optional transaction-time guard, checked after receipt lookup.
        pub time: TimeGuard,
        /// Borrowed pre-mutation comparisons.
        pub predicates: *const Predicate,
        /// Comparison count; no arbitrary item cap.
        pub predicates_len: usize,
        /// Borrowed atomic effects; overlapping selectors are refused.
        pub mutations: *const Mutation,
        /// Mutation count; no arbitrary item cap.
        pub mutations_len: usize,
        /// Bounded original result/reference octets, never a plaintext secret response.
        pub result: Blob,
    }

    /// One host-owned read descriptor, in input-address order.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ReadValue {
        /// VALUE_ABSENT or VALUE_FOUND.
        pub found: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Returned octets inside the written host byte buffer; empty if absent.
        pub value: Blob,
    }

    /// Host-owned descriptors and backing bytes for a coherent read.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct HostValues {
        /// Writable descriptors.
        pub items: *mut ReadValue,
        /// Descriptor capacity.
        pub items_cap: usize,
        /// Backing byte capacity.
        pub bytes: HostBuf,
    }

    /// Coherent authoritative multi-address read.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ReadIn {
        /// Shared call head.
        pub head: InHead,
        /// Target dataset identity.
        pub dataset: [u8; 16],
        /// Borrowed exact address array.
        pub addresses: *const Address,
        /// Address count.
        pub addresses_len: usize,
        /// Evaluated at the same serialization point as the read.
        pub time: TimeGuard,
        /// Host-owned response buffers.
        pub values: HostValues,
    }

    /// Read result; a failed time guard returns no values.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ReadOut {
        /// Shared answer head; payloads are host-owned.
        pub head: OutHead,
        /// READ_VALUES or READ_TIME_GUARD_FAILED on READY.
        pub code: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Authoritative serialization time, in Unix seconds.
        pub observed_at: u64,
        /// Stable identity of the authoritative clock source.
        pub authority: [u8; 16],
        /// Returned descriptors; one per requested address on READ_VALUES.
        pub items_written: u64,
        /// Backing bytes written.
        pub bytes_written: u64,
        /// Full required descriptor count on short FAILED; zero otherwise.
        pub needed_items: u64,
        /// Full required byte count on short FAILED; zero otherwise.
        pub needed_bytes: u64,
    }

    /// One ordered scan row inside host-owned byte storage.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ScanRow {
        /// Raw key bytes inside the written host buffer.
        pub key: Bytes,
        /// Opaque value inside the written host buffer.
        pub value: Blob,
    }

    /// Host-owned scan descriptors and their backing bytes.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct HostRows {
        /// Writable row descriptors.
        pub items: *mut ScanRow,
        /// Descriptor capacity.
        pub items_cap: usize,
        /// Backing bytes, including the continuation cursor.
        pub bytes: HostBuf,
    }

    /// Coherent namespace page; continuation is exclusive and generation checked.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ScanIn {
        /// Shared call head.
        pub head: InHead,
        /// Target dataset identity.
        pub dataset: [u8; 16],
        /// Core-assigned namespace identity.
        pub namespace: [u8; 16],
        /// Raw key prefix.
        pub prefix: Bytes,
        /// Exclusive raw cursor when SCAN_AFTER is set.
        pub after: Bytes,
        /// Expected generation when SCAN_GENERATION is set.
        pub generation: u64,
        /// SCAN_AFTER, SCAN_GENERATION and/or SCAN_ALLOW_CHANGE.
        pub flags: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Maximum rows in this page.
        pub max_items: u64,
        /// Maximum total returned key/value bytes in this page.
        pub max_bytes: u64,
        /// Host-owned page response buffers.
        pub rows: HostRows,
    }

    /// Explicit continuation/exhaustion; pages are not an implicit snapshot.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ScanOut {
        /// Shared answer head; payloads are host-owned.
        pub head: OutHead,
        /// SCAN_PAGE or SCAN_STALE on READY.
        pub code: u32,
        /// SCAN_EXHAUSTED or SCAN_CONTINUE for a page; zero for stale.
        pub continuation: u32,
        /// Namespace generation observed atomically with the page.
        pub generation: u64,
        /// Exclusive cursor inside host bytes; empty on exhaustion.
        pub next: Bytes,
        /// Returned row descriptor count.
        pub items_written: u64,
        /// Host bytes used, including next cursor storage.
        pub bytes_written: u64,
        /// Full required descriptor count on short FAILED; zero otherwise.
        pub needed_items: u64,
        /// Full required byte count on short FAILED; zero otherwise.
        pub needed_bytes: u64,
    }

    /// Atomic immutable candidate submission; replay uses identical candidate bytes.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct CommitIn {
        /// Shared call head.
        pub head: InHead,
        /// Borrowed immutable candidate.
        pub candidate: Candidate,
        /// Host-owned original applied result buffer.
        pub result: HostBuf,
    }

    /// Execution decision; uncertainty is never converted to no-effect rejection.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct CommitOut {
        /// Shared answer head; payloads are host-owned.
        pub head: OutHead,
        /// COMMIT_APPLIED through COMMIT_EXPIRED_UNKNOWN on READY.
        pub code: u32,
        /// Must be zero.
        pub _reserved: u32,
        /// Authoritative serialization time, or original receipt observation on replay.
        pub observed_at: u64,
        /// Stable identity of the authoritative clock source.
        pub authority: [u8; 16],
        /// Original result bytes written only for COMMIT_APPLIED.
        pub written: u64,
        /// Full result size on short FAILED; zero otherwise.
        pub needed: u64,
    }

    /// Observe authoritative time for this dataset.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ClockIn {
        /// Shared call head.
        pub head: InHead,
        /// Target dataset identity.
        pub dataset: [u8; 16],
    }

    /// Authoritative UTC observation; never an ordering/identity source.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ClockOut {
        /// Shared answer head.
        pub head: OutHead,
        /// UTC seconds since Unix epoch.
        pub observed_at: u64,
        /// Stable identity of the authoritative clock source.
        pub authority: [u8; 16],
    }

    /// Retained native inspection/upgrade session before ordinary OPEN.
    /// Nested inputs remain borrowed for the call/ticket and exact short-buffer replay.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct BootstrapIn {
        /// Shared call head.
        pub head: InHead,
        /// Host-owned services retained with the native session.
        pub host: *const HostTables,
        /// Borrowed settings for the retained session.
        pub settings: Blob,
        /// Borrowed secret array; NULL only when empty.
        pub secrets: *const Blob,
        /// Number of borrowed secrets.
        pub secrets_len: usize,
        /// Host generation identity.
        pub generation: u64,
        /// Versioned tagged lifecycle request; see persistence::lifecycle.
        pub request: Blob,
        /// Host-owned versioned lifecycle response buffer.
        pub result: HostBuf,
    }

    /// Lifecycle response; uncertainty never becomes a no-effect rejection.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct BootstrapOut {
        /// Shared answer head; a short buffer uses FAILED.
        pub head: OutHead,
        /// Retained native instance on every allocated crossing, including
        /// PENDING, short buffers and errors; teardown is legal before OPEN.
        pub instance: *mut core::ffi::c_void,
        /// Response octets written only on READY.
        pub written: u64,
        /// Full required size on short FAILED; replay the exact request/session.
        pub needed: u64,
    }

    /// Primitive table; every kind slot is mandatory.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct Ops {
        /// Unchanged lifecycle table.
        pub head: OpsHead,
        /// Coherent exact-address read.
        pub read: Option<Op>,
        /// Ordered bounded namespace scan.
        pub scan: Option<Op>,
        /// Atomic conditional candidate and receipt.
        pub commit: Option<Op>,
        /// Authoritative UTC observation.
        pub clock: Option<Op>,
        /// Pre-open native inspection and upgrade lifecycle.
        pub bootstrap: Option<Op>,
    }

}

/// Inclusive lower UTC bound is present.
pub const TIME_NOT_BEFORE: u32 = 1;
/// Exclusive upper UTC bound is present.
pub const TIME_BEFORE: u32 = 2;
/// The compared address is absent.
pub const PREDICATE_ABSENT: u32 = 1;
/// The compared value equals expected octets.
pub const PREDICATE_EXACT: u32 = 2;
/// Replace the value explicitly.
pub const MUTATION_PUT: u32 = 1;
/// Delete one exact address.
pub const MUTATION_DELETE: u32 = 2;
/// Atomically delete prefix matches of exactly exact_length bytes.
pub const MUTATION_DELETE_RANGE: u32 = 3;
/// No value exists at this requested address.
pub const VALUE_ABSENT: u32 = 0;
/// A value exists, including an explicitly empty value.
pub const VALUE_FOUND: u32 = 1;
/// Coherent values were observed.
pub const READ_VALUES: u32 = 1;
/// Read serialization fell outside its allowed interval.
pub const READ_TIME_GUARD_FAILED: u32 = 2;
/// An exclusive cursor is present, including an empty key cursor.
pub const SCAN_AFTER: u32 = 1;
/// Compare the supplied namespace generation.
pub const SCAN_GENERATION: u32 = 2;
/// Display scan explicitly permits generation change between pages.
pub const SCAN_ALLOW_CHANGE: u32 = 4;
/// A coherent ordered page was returned.
pub const SCAN_PAGE: u32 = 1;
/// Generation changed; no page was returned.
pub const SCAN_STALE: u32 = 2;
/// No further matching rows.
pub const SCAN_EXHAUSTED: u32 = 1;
/// Another page exists; next is its exclusive cursor.
pub const SCAN_CONTINUE: u32 = 2;
/// Effects and receipt committed; replay returns original result.
pub const COMMIT_APPLIED: u32 = 1;
/// This execution did not apply because a predicate failed.
pub const COMMIT_CONDITION_CONFLICT: u32 = 2;
/// This execution did not apply because the time guard failed.
pub const COMMIT_TIME_GUARD_FAILED: u32 = 3;
/// This identity is already bound to another candidate.
pub const COMMIT_OPID_CONFLICT: u32 = 4;
/// Receipt unavailable and execution authority retired; never execute anew.
pub const COMMIT_EXPIRED_UNKNOWN: u32 = 5;

/// Primitive names, in mandatory table order.
pub const NAMES: [&str; 5] = ["read", "scan", "commit", "clock", "bootstrap"];
/// Primitive contracts; all may pend through the existing driver mechanism.
pub const OPS: [OpContract; 5] = [
    OpContract {
        slot: slot::READ,
        request_path: true,
        may_pend: true,
        max_in: core::mem::size_of::<ReadIn>(),
        max_out: core::mem::size_of::<ReadOut>(),
        deadline: DeadlineClass::Call,
    },
    OpContract {
        slot: slot::SCAN,
        request_path: true,
        may_pend: true,
        max_in: core::mem::size_of::<ScanIn>(),
        max_out: core::mem::size_of::<ScanOut>(),
        deadline: DeadlineClass::Call,
    },
    OpContract {
        slot: slot::COMMIT,
        request_path: true,
        may_pend: true,
        max_in: core::mem::size_of::<CommitIn>(),
        max_out: core::mem::size_of::<CommitOut>(),
        deadline: DeadlineClass::Call,
    },
    OpContract {
        slot: slot::CLOCK,
        request_path: true,
        may_pend: true,
        max_in: core::mem::size_of::<ClockIn>(),
        max_out: core::mem::size_of::<ClockOut>(),
        deadline: DeadlineClass::Call,
    },
    OpContract {
        slot: slot::BOOTSTRAP,
        request_path: false,
        may_pend: true,
        max_in: core::mem::size_of::<BootstrapIn>(),
        max_out: core::mem::size_of::<BootstrapOut>(),
        deadline: DeadlineClass::Call,
    },
];

/// Every v4 shape, in fingerprint fold order.
pub const LAYOUT_SHAPES: &[&[u64]] = &[
    HostBuf::LAYOUT,
    Bytes::LAYOUT,
    Address::LAYOUT,
    TimeGuard::LAYOUT,
    AttemptId::LAYOUT,
    Predicate::LAYOUT,
    Mutation::LAYOUT,
    Candidate::LAYOUT,
    ReadValue::LAYOUT,
    HostValues::LAYOUT,
    ReadIn::LAYOUT,
    ReadOut::LAYOUT,
    ScanRow::LAYOUT,
    HostRows::LAYOUT,
    ScanIn::LAYOUT,
    ScanOut::LAYOUT,
    CommitIn::LAYOUT,
    CommitOut::LAYOUT,
    ClockIn::LAYOUT,
    ClockOut::LAYOUT,
    BootstrapIn::LAYOUT,
    BootstrapOut::LAYOUT,
    Ops::LAYOUT,
];
/// Fingerprint of the primitive shapes, independent from the legacy business layout.
pub const LAYOUT_FINGERPRINT: u64 = 0x9c169c7bbc780b53;

// SAFETY: C structs leading with the shared head and containing only plain data.
unsafe impl crate::abi::sdk::door::AbiIn for ReadIn {}
unsafe impl crate::abi::sdk::door::AbiIn for ScanIn {}
unsafe impl crate::abi::sdk::door::AbiIn for CommitIn {}
unsafe impl crate::abi::sdk::door::AbiIn for ClockIn {}
unsafe impl crate::abi::sdk::door::AbiIn for BootstrapIn {}
unsafe impl crate::abi::sdk::door::AbiOut for ReadOut {}
unsafe impl crate::abi::sdk::door::AbiOut for ScanOut {}
unsafe impl crate::abi::sdk::door::AbiOut for CommitOut {}
unsafe impl crate::abi::sdk::door::AbiOut for ClockOut {}
unsafe impl crate::abi::sdk::door::AbiOut for BootstrapOut {}

/// Safe output-envelope checks. The future admitted loader must additionally
/// validate every returned descriptor/cursor against host-owned written bytes,
/// inspect Blob format/flags, and validate input spans with checked arithmetic.
/// No raw output pointer is dereferenced here.
pub mod check {
    use super::*;
    use crate::abi::mechanism::call::Outcome;
    use crate::abi::mechanism::check::{code, fault, result, results, Dim, Fault, Rule};

    fn zero(value: u64, field: &'static str) -> Result<(), Fault> {
        if value != 0 {
            return Err(fault(Rule::Contradiction, field));
        }
        Ok(())
    }

    fn dims(
        outcome: Outcome,
        items: u64,
        bytes: u64,
        needed_items: u64,
        needed_bytes: u64,
        items_cap: usize,
        bytes_cap: usize,
    ) -> Result<(), Fault> {
        results(
            outcome,
            "store.v4.buffers",
            &[
                Dim {
                    written: items,
                    needed: needed_items,
                    cap: items_cap as u64,
                    max: usize::MAX as u64,
                    field: "store.v4.items",
                },
                Dim {
                    written: bytes,
                    needed: needed_bytes,
                    cap: bytes_cap as u64,
                    max: usize::MAX as u64,
                    field: "store.v4.bytes",
                },
            ],
        )?;
        if outcome != Outcome::Ready {
            zero(items, "store.v4.items_on_failure")?;
            zero(bytes, "store.v4.bytes_on_failure")?;
        }
        Ok(())
    }

    /// Check coherent-read status, fixed fields and host-buffer dimensions.
    ///
    /// # Errors
    /// A status, reserved field, count or short-buffer convention is malformed.
    pub fn read(outcome: Outcome, input: &ReadIn, out: &ReadOut) -> Result<(), Fault> {
        zero(u64::from(out._reserved), "store.v4.read.reserved")?;
        dims(
            outcome,
            out.items_written,
            out.bytes_written,
            out.needed_items,
            out.needed_bytes,
            input.values.items_cap,
            input.values.bytes.cap,
        )?;
        if outcome == Outcome::Ready {
            code(
                u64::from(out.code),
                u64::from(READ_VALUES),
                u64::from(READ_TIME_GUARD_FAILED),
                "store.v4.read.code",
            )?;
            if out.code == READ_VALUES {
                if out.items_written != input.addresses_len as u64 {
                    return Err(fault(Rule::Contradiction, "store.v4.read.count"));
                }
            } else {
                zero(out.items_written, "store.v4.read.time_items")?;
                zero(out.bytes_written, "store.v4.read.time_bytes")?;
            }
        }
        Ok(())
    }

    /// Check page status, explicit continuation and host-buffer dimensions.
    ///
    /// # Errors
    /// A status, reserved field, count or short-buffer convention is malformed.
    pub fn scan(outcome: Outcome, input: &ScanIn, out: &ScanOut) -> Result<(), Fault> {
        dims(
            outcome,
            out.items_written,
            out.bytes_written,
            out.needed_items,
            out.needed_bytes,
            input.rows.items_cap,
            input.rows.bytes.cap,
        )?;
        if outcome == Outcome::Ready {
            code(
                u64::from(out.code),
                u64::from(SCAN_PAGE),
                u64::from(SCAN_STALE),
                "store.v4.scan.code",
            )?;
            if out.code == SCAN_PAGE {
                code(
                    u64::from(out.continuation),
                    u64::from(SCAN_EXHAUSTED),
                    u64::from(SCAN_CONTINUE),
                    "store.v4.scan.continuation",
                )?;
                if out.items_written > input.max_items {
                    return Err(fault(Rule::OverCap, "store.v4.scan.max_items"));
                }
                if out.continuation == SCAN_EXHAUSTED {
                    zero(out.next.len as u64, "store.v4.scan.exhausted_cursor")?;
                }
            } else {
                zero(
                    u64::from(out.continuation),
                    "store.v4.scan.stale_continuation",
                )?;
                zero(out.items_written, "store.v4.scan.stale_items")?;
                zero(out.bytes_written, "store.v4.scan.stale_bytes")?;
                zero(out.next.len as u64, "store.v4.scan.stale_cursor")?;
            }
        }
        Ok(())
    }

    /// Check commit verdict and original result buffer dimensions.
    /// A short result preserves exact candidate/id custody for receipt replay.
    ///
    /// # Errors
    /// A verdict, reserved field or short-buffer convention is malformed.
    pub fn commit(outcome: Outcome, input: &CommitIn, out: &CommitOut) -> Result<(), Fault> {
        zero(u64::from(out._reserved), "store.v4.commit.reserved")?;
        result(
            outcome,
            out.written,
            out.needed,
            input.result.cap as u64,
            usize::MAX as u64,
            "store.v4.commit.result",
        )?;
        if outcome == Outcome::Ready {
            code(
                u64::from(out.code),
                u64::from(COMMIT_APPLIED),
                u64::from(COMMIT_EXPIRED_UNKNOWN),
                "store.v4.commit.code",
            )?;
            if out.code != COMMIT_APPLIED {
                zero(out.written, "store.v4.commit.unapplied_result")?;
            }
        } else {
            zero(out.written, "store.v4.commit.result_on_failure")?;
        }
        Ok(())
    }
    /// Check lifecycle response capacity without discarding retained instances.
    /// Pending/error pointers are legal and remain available for teardown.
    /// Unknown transport outcomes must stay FAILED; no verdict is inferred here.
    ///
    /// # Errors
    /// Response lengths violate capacity or short-buffer conventions.
    pub fn bootstrap(
        outcome: Outcome,
        input: &BootstrapIn,
        out: &BootstrapOut,
    ) -> Result<(), Fault> {
        result(
            outcome,
            out.written,
            out.needed,
            input.result.cap as u64,
            usize::MAX as u64,
            "store.v4.bootstrap.result",
        )?;
        if outcome != Outcome::Ready {
            zero(out.written, "store.v4.bootstrap.result_on_failure")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/v4_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/check_tests.rs"]
mod check_tests;
