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

use crate::abi::mechanism::check::{self};

/// [`DirectoryResult::state`], [`DirectoryCreateIn::state`]: active.
pub const STATE_ACTIVE: u32 = 1;
/// Inactive: the kernel holds a linked principal whose subject is inactive.
pub const STATE_INACTIVE: u32 = 2;

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
