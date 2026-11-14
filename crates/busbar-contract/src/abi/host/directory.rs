// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `directory` HOST SERVICES (1.6.0, auth v4): a provisioning auth instance's neutral
//! subject/group/member records, kept by the kernel. Seven services, appended to
//! [`HostSlots`](super::service::HostSlots) after `hook.child` ([`super::service::op`]
//! `DIRECTORY_GET` … `DIRECTORY_DELETE`), on the shared service call shape.
//!
//! WHO MAY CALL. Auth instances only ([`super::access`]), and at call time only an instance whose
//! Statement states [`CAP_PROVISION`](crate::abi::auth::CAP_PROVISION) and whose definition carries
//! a `provisioning:` block; any other caller is REFUSED. Each instance sees only its own records.
//! Callable from `serve` and from `tick` (pull-sync writes state `SOURCE_PULL`). Every service may
//! pend.
//!
//! WHAT THE KERNEL KNOWS. Subjects, groups, members, a state, opaque documents, plugin-named unique
//! indexes and maintained counts. It parses no document and offers no query language: exact
//! [`op::DIRECTORY_LOOKUP`](super::service::op::DIRECTORY_LOOKUP) over a unique index and ordered
//! [`op::DIRECTORY_SCAN`](super::service::op::DIRECTORY_SCAN) are the whole read surface.
//!
//! ANSWERS. A domain outcome (not found, conflict, stale version, the mass guard) is READY with a
//! [`DirectoryResult::code`] written into the caller's `result`; FAILED and REFUSED mean the call
//! did not reach the directory (store fault, no grant, a malformed `in`). Bytes go into the
//! caller's [`ServiceBufs`] under the short-buffer rule.

use crate::abi::mechanism::call::{AbiStr, Blob};
use crate::abi::mechanism::check::{self, fault, Fault, Rule};

use super::service::{ServiceBufs, ServiceHead};

/// [`DirectoryGetIn::kind`] and friends: a subject (a person or account).
pub const DIR_SUBJECT: u32 = 1;
/// A group.
pub const DIR_GROUP: u32 = 2;
/// A group's members: scan and count only, scoped by the group id.
pub const DIR_MEMBER: u32 = 3;

/// [`DirectoryResult::state`], [`DirectoryCreateIn::state`]: active.
pub const STATE_ACTIVE: u32 = 1;
/// Inactive: the kernel holds a linked principal whose subject is inactive.
pub const STATE_INACTIVE: u32 = 2;

/// [`DirectoryCreateIn::source`]: pushed by a client through `serve`.
pub const SOURCE_PUSH: u32 = 1;
/// Pulled by the plugin itself from `tick`.
pub const SOURCE_PULL: u32 = 2;

/// [`DirectoryResult::code`]: done.
pub const DIR_OK: u32 = 0;
/// No such record.
pub const DIR_NOT_FOUND: u32 = 1;
/// A unique index already holds the value; [`DirectoryResult::index`] names the slot, in the
/// order the `in` named the indexes. Nothing was written.
pub const DIR_CONFLICT: u32 = 2;
/// `expected_version` is not the record's. Nothing was written.
pub const DIR_PRECONDITION: u32 = 3;
/// Over a kernel cap (indexes, members per call, scan size). Nothing was written.
pub const DIR_TOO_MANY: u32 = 4;
/// The kernel refused the content (size, UTF-8, control characters, an unknown member id, a
/// change to the linked index). Nothing was written.
pub const DIR_INVALID: u32 = 5;
/// The mass-deprovision guard holds: the write would affect more linked principals than the
/// window allows. Nothing was written; an operator releases the guard.
pub const DIR_GUARD: u32 = 6;

/// [`DirectoryApplyIn::flags`]: replace the document.
pub const APPLY_DOCUMENT: u32 = 1;
/// Replace the index values (the full set named).
pub const APPLY_INDEXES: u32 = 2;
/// Set the state.
pub const APPLY_STATE: u32 = 4;
/// Replace the whole member set with [`DirectoryApplyIn::members_replace`].
pub const APPLY_REPLACE_MEMBERS: u32 = 8;
/// Every apply flag.
pub const APPLY_ALL: u32 = APPLY_DOCUMENT | APPLY_INDEXES | APPLY_STATE | APPLY_REPLACE_MEMBERS;

/// The most distinct index names per kind per instance.
pub const MAX_INDEXES: usize = 4;
/// The longest index name: `[a-z0-9_]{1,32}`.
pub const MAX_INDEX_NAME: usize = 32;
/// The longest index value, in bytes.
pub const MAX_INDEX_VALUE: usize = 256;
/// The longest record id, in bytes (the kernel mints UUIDv4 ids; members name them).
pub const MAX_ID: usize = 64;
/// The largest document, in bytes.
pub const MAX_DOCUMENT: usize = 64 * 1024;
/// The most member changes in one apply (add + remove + replace).
pub const MAX_MEMBERS_PER_APPLY: usize = 10_000;
/// The most rows one scan answers.
pub const MAX_SCAN: u32 = 500;

/// The kernel's answer beside the bytes: written by the host on READY.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectoryResult {
    /// [`DIR_OK`] … [`DIR_GUARD`].
    pub code: u32,
    /// With [`DIR_CONFLICT`]: which index slot collided.
    pub index: u32,
    /// The record's version after the call (get, create, apply); `0` otherwise.
    pub version: u64,
    /// The record's state (get, create, apply on a subject); `0` otherwise.
    pub state: u32,
    /// Scan: `1` when more rows follow the last one written.
    pub more: u32,
    /// Count: the total; scan: rows written.
    pub count: u64,
    /// Count of subjects: how many are active.
    pub active: u64,
}

/// `directory.get`'s `in`. READY + [`DIR_OK`]: span 0 is the record (key = id, value = document),
/// spans 1.. its index values (key = name, value = value).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryGetIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`].
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The record id.
    pub id: AbiStr,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
    /// Where the record goes.
    pub into: ServiceBufs,
}

/// `directory.lookup`'s `in`: the id a unique index maps `value` to. READY + [`DIR_OK`]: span 0's
/// key is the id.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryLookupIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`].
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The index name.
    pub index: AbiStr,
    /// The value, compared byte for byte (the plugin normalises it).
    pub value: AbiStr,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
    /// Where the id goes.
    pub into: ServiceBufs,
}

/// `directory.scan`'s `in`: records in id order after `after`. One span per row (key = id, value
/// = document; for [`DIR_MEMBER`], key = the member subject id, value empty).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryScanIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`] | [`DIR_MEMBER`].
    pub kind: u32,
    /// The most rows; `0` or over [`MAX_SCAN`] means [`MAX_SCAN`].
    pub limit: u32,
    /// For [`DIR_MEMBER`]: the group id; absent otherwise.
    pub scope: AbiStr,
    /// The cursor: the last id already seen; absent = from the first.
    pub after: AbiStr,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
    /// Where the rows go.
    pub into: ServiceBufs,
}

/// `directory.count`'s `in`: the maintained count, never a scan.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryCountIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`] | [`DIR_MEMBER`].
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// For [`DIR_MEMBER`]: the group id; absent otherwise.
    pub scope: AbiStr,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
}

/// `directory.create`'s `in`. READY + [`DIR_OK`]: span 0's key is the kernel-minted id.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryCreateIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`].
    pub kind: u32,
    /// [`STATE_ACTIVE`] | [`STATE_INACTIVE`] (subjects; groups state `0`).
    pub state: u32,
    /// [`SOURCE_PUSH`] | [`SOURCE_PULL`].
    pub source: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The opaque document, at most [`MAX_DOCUMENT`].
    pub document: Blob,
    /// Index name/value pairs, interleaved; each value unique per (kind, name).
    pub indexes: *const AbiStr,
    /// How many `AbiStr` entries `indexes` holds (twice the index count).
    pub indexes_len: usize,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
    /// Where the id goes.
    pub into: ServiceBufs,
}

/// `directory.apply`'s `in`: ONE conditional write of the document, the indexes, the state and
/// the member delta. All of it lands or none of it does.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryApplyIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`].
    pub kind: u32,
    /// [`APPLY_DOCUMENT`] | [`APPLY_INDEXES`] | [`APPLY_STATE`] | [`APPLY_REPLACE_MEMBERS`].
    pub flags: u32,
    /// With [`APPLY_STATE`]: the new state.
    pub state: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The record id.
    pub id: AbiStr,
    /// The version the caller read; `0` = any.
    pub expected_version: u64,
    /// With [`APPLY_DOCUMENT`]: the new document.
    pub document: Blob,
    /// With [`APPLY_INDEXES`]: the full index set, interleaved name/value.
    pub indexes: *const AbiStr,
    /// How many `AbiStr` entries `indexes` holds.
    pub indexes_len: usize,
    /// Groups: subject ids to add.
    pub members_add: *const AbiStr,
    /// How many.
    pub members_add_len: usize,
    /// Groups: subject ids to remove.
    pub members_remove: *const AbiStr,
    /// How many.
    pub members_remove_len: usize,
    /// Groups, with [`APPLY_REPLACE_MEMBERS`]: the whole new member set.
    pub members_replace: *const AbiStr,
    /// How many.
    pub members_replace_len: usize,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
}

/// `directory.delete`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryDeleteIn {
    /// The head.
    pub head: ServiceHead,
    /// [`DIR_SUBJECT`] | [`DIR_GROUP`].
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The record id.
    pub id: AbiStr,
    /// The version the caller read; `0` = any.
    pub expected_version: u64,
    /// Where the kernel writes its answer.
    pub result: *mut DirectoryResult,
}

/// A record kind a get/lookup/create/apply/delete may name.
pub const fn check_record_kind(kind: u32, field: &'static str) -> Result<(), Fault> {
    match kind {
        DIR_SUBJECT | DIR_GROUP => Ok(()),
        _ => Err(fault(Rule::Foreign, field)),
    }
}

/// A kind a scan/count may name.
pub const fn check_scan_kind(kind: u32, field: &'static str) -> Result<(), Fault> {
    match kind {
        DIR_SUBJECT | DIR_GROUP | DIR_MEMBER => Ok(()),
        _ => Err(fault(Rule::Foreign, field)),
    }
}

/// The result slot is the caller's and present.
pub fn check_result(result: *const DirectoryResult, field: &'static str) -> Result<(), Fault> {
    if result.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    Ok(())
}

/// An interleaved name/value list: an even count, a NULL pointer only with no entries.
pub fn check_pairs(ptr: *const AbiStr, len: usize, field: &'static str) -> Result<(), Fault> {
    check::listed(ptr, len, field)?;
    if len % 2 != 0 {
        return Err(fault(Rule::Contradiction, field));
    }
    if len / 2 > MAX_INDEXES {
        return Err(fault(Rule::OverMax, field));
    }
    Ok(())
}

/// The host's check of an apply `in`'s scalars and list framing (content is the kernel's to judge).
pub fn check_apply_in(i: &DirectoryApplyIn) -> Result<(), Fault> {
    check_record_kind(i.kind, "directory_apply.kind")?;
    check::bits(
        u64::from(i.flags),
        u64::from(APPLY_ALL),
        "directory_apply.flags",
    )?;
    check_result(i.result, "directory_apply.result")?;
    check_pairs(i.indexes, i.indexes_len, "directory_apply.indexes")?;
    check::listed(
        i.members_add,
        i.members_add_len,
        "directory_apply.members_add",
    )?;
    check::listed(
        i.members_remove,
        i.members_remove_len,
        "directory_apply.members_remove",
    )?;
    check::listed(
        i.members_replace,
        i.members_replace_len,
        "directory_apply.members_replace",
    )?;
    if i.flags & APPLY_REPLACE_MEMBERS == 0 && i.members_replace_len != 0 {
        return Err(fault(
            Rule::Contradiction,
            "directory_apply.members_replace",
        ));
    }
    if i.kind == DIR_SUBJECT
        && (i.members_add_len | i.members_remove_len | i.members_replace_len != 0
            || i.flags & APPLY_REPLACE_MEMBERS != 0)
    {
        return Err(fault(Rule::Contradiction, "directory_apply.members"));
    }
    Ok(())
}
