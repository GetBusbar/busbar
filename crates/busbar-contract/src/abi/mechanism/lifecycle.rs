// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIFECYCLE: the slot set every kind's table leads with ([`OpsHead`]), and the `in`/`out` of
//! each slot. Every slot is an [`Op`]; a NULL slot refuses the load (there is no "unsupported").
//! There is no poll slot: after a wake the host re-invokes the same op with
//! [`super::call::FLAG_RESUME`], the same ticket and the same `in`/`out`.
//!
//! CONCURRENCY. An instance is shared across workers. Ops on DISTINCT tickets may run concurrently;
//! ops on ONE ticket are serialized by the host and never overlap. The lifecycle slots `open`,
//! `refresh`, `retire` and `close` never run concurrently with each other on one instance; `tick`
//! and `drive` may run concurrently with request ops. Serialization does not apply to a
//! [`Ticket::NONE`] call, and PENDING answered on one is FAULT.
//!
//! SLOT LAYOUT. A kind's table is [`OpsHead`] followed by contiguous `Option<Op>` fields: kind op `k`
//! is at slot index [`LIFECYCLE_SLOTS`]` + k`. [`OpsHead::slots`] and [`OpsHead::size`] must EQUAL
//! the host's values for that kind's ABI version, or the load is refused.

use super::call::{Blob, InHead, Op, OutHead};
use super::ticket::{HostTables, Ticket};

/// [`InHead::op`] of each lifecycle slot, in table order. A kind's own ops number on from
/// [`LIFECYCLE_SLOTS`].
pub mod slot {
    /// `validate`.
    pub const VALIDATE: u32 = 0;
    /// `open`.
    pub const OPEN: u32 = 1;
    /// `refresh`.
    pub const REFRESH: u32 = 2;
    /// `retire`.
    pub const RETIRE: u32 = 3;
    /// `tick`.
    pub const TICK: u32 = 4;
    /// `drive`.
    pub const DRIVE: u32 = 5;
    /// `cancel`.
    pub const CANCEL: u32 = 6;
    /// `release`.
    pub const RELEASE: u32 = 7;
    /// `close`.
    pub const CLOSE: u32 = 8;
}

/// How many lifecycle slots [`OpsHead`] holds.
pub const LIFECYCLE_SLOTS: u32 = 9;

/// The head of every kind's ops table: the lifecycle, one [`Op`] per slot, in [`slot`] order.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpsHead {
    /// `size_of` the whole kind table; equal to the host's for the kind's ABI version.
    pub size: u32,
    /// How many slots the whole kind table holds, lifecycle included; equal to the host's.
    pub slots: u32,
    /// Pure validation of a settings blob. In [`ValidateIn`], out [`OutHead`].
    pub validate: Option<Op>,
    /// Boot, on the control lane; may pend. In [`OpenIn`], out [`OpenOut`].
    pub open: Option<Op>,
    /// Reload; may pend. In [`GenIn`], out [`OutHead`].
    pub refresh: Option<Op>,
    /// After the RCU drain of a generation. In [`GenIn`], out [`OutHead`].
    pub retire: Option<Op>,
    /// The kernel clock. In [`TickIn`], out [`TickOut`].
    pub tick: Option<Op>,
    /// A driver ticket woke. In [`DriveIn`], out [`OutHead`].
    pub drive: Option<Op>,
    /// A deadline, or a client drop on a request-path op. In [`CancelIn`], out [`CancelOut`].
    pub cancel: Option<Op>,
    /// The host is done with off-path or secret bytes. In [`ReleaseIn`], out [`OutHead`].
    pub release: Option<Op>,
    /// Shutdown, or a retired instance. In [`InHead`], out [`OutHead`].
    pub close: Option<Op>,
}

/// `validate`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ValidateIn {
    /// The head.
    pub head: InHead,
    /// The settings blob.
    pub settings: Blob,
}

/// `open`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenIn {
    /// The head.
    pub head: InHead,
    /// The host tables.
    pub host: *const HostTables,
    /// The settings blob.
    pub settings: Blob,
    /// The resolved secrets, each a [`super::call::BLOB_SECRET`] blob: one per
    /// [`super::door::Statement::secret_refs`] key, in that order.
    pub secrets: *const Blob,
    /// How many.
    pub secrets_len: usize,
    /// The generation this instance opens at.
    pub generation: u64,
}

/// `open`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenOut {
    /// The head.
    pub head: OutHead,
    /// The instance every later call is made on.
    pub instance: *mut std::os::raw::c_void,
}

/// `refresh`'s and `retire`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GenIn {
    /// The head.
    pub head: InHead,
    /// The generation.
    pub generation: u64,
}

/// `tick`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TickIn {
    /// The head.
    pub head: InHead,
    /// Now, on the kernel's coarse clock (nanoseconds).
    pub now_ns: u64,
}

/// `tick`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TickOut {
    /// The head.
    pub head: OutHead,
    /// When to tick next; `0` = never.
    pub next_tick_ns: u64,
}

/// `drive`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriveIn {
    /// The head.
    pub head: InHead,
    /// The driver ticket that woke: persistent, owned by the instance, outside `max_inflight`.
    pub driver: Ticket,
}

/// `cancel`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CancelIn {
    /// The head.
    pub head: InHead,
    /// The ticket whose op is cancelled.
    pub ticket: Ticket,
}

/// `cancel`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CancelOut {
    /// The head.
    pub head: OutHead,
    /// The kind's disposition of the cancelled op (its own vocabulary, `abi/<kind>/`).
    pub disposition: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `release`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReleaseIn {
    /// The head.
    pub head: InHead,
    /// The lease an `out` handed the host.
    pub lease: u64,
}
