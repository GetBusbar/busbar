// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O TABLE, `io.*` (`BUSBAR-1.6.0.md` THE DESIGN, the connections section), as a `#[repr(C)]` table of host slots.

use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::check::{self};

pub use crate::abi::host::service::{ServiceFn, ServiceHead, ServiceOut};

/// The index of each slot in [`IoSlots`], in table order.
pub mod op {
    /// `io.open`.
    pub const OPEN: u32 = 0;
    /// `io.listen`.
    pub const LISTEN: u32 = 1;
    /// `io.accept`.
    pub const ACCEPT: u32 = 2;
    /// `io.read`.
    pub const READ: u32 = 3;
    /// `io.write`.
    pub const WRITE: u32 = 4;
    /// `io.ready`.
    pub const READY: u32 = 5;
    /// `io.shut`.
    pub const SHUT: u32 = 6;
    /// `io.close`.
    pub const CLOSE: u32 = 7;
    /// `io.spawn`.
    pub const SPAWN: u32 = 8;
    /// `io.ends`.
    pub const ENDS: u32 = 9;
}

/// How many slots [`IoSlots`] holds.
pub const SLOTS: u32 = 10;

/// The most bytes an address the host writes may take: the caller lends at least this many.
pub const MAX_ADDR: usize = 256;

/// Whether a slot may answer PENDING, and so is callable only inside a ticketed op. `false` for an op that always answers at once.
#[must_use]
pub const fn may_pend(slot: u32) -> bool {
    matches!(slot, op::ACCEPT | op::READ | op::WRITE | op::READY)
}

/// THE HOST'S I/O TABLE: one [`ServiceFn`] per [`op`], in index order. A NULL slot is one this host
/// does not offer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoSlots {
    /// `size_of::<IoSlots>()`.
    pub size: u32,
    /// [`SLOTS`].
    pub slots: u32,
    /// [`op::OPEN`], in [`OpenIn`].
    pub open: Option<ServiceFn>,
    /// [`op::LISTEN`], in [`ListenIn`].
    pub listen: Option<ServiceFn>,
    /// [`op::ACCEPT`], in [`AddrIn`].
    pub accept: Option<ServiceFn>,
    /// [`op::READ`], in [`ReadIn`].
    pub read: Option<ServiceFn>,
    /// [`op::WRITE`], in [`WriteIn`].
    pub write: Option<ServiceFn>,
    /// [`op::READY`], in [`ReadyIn`].
    pub ready: Option<ServiceFn>,
    /// [`op::SHUT`], in [`ShutIn`].
    pub shut: Option<ServiceFn>,
    /// [`op::CLOSE`], in [`HandleIn`].
    pub close: Option<ServiceFn>,
    /// [`op::SPAWN`], in [`SpawnIn`].
    pub spawn: Option<ServiceFn>,
    /// [`op::ENDS`], in [`AddrIn`].
    pub ends: Option<ServiceFn>,
}

/// `io.listen`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ListenIn {
    /// The head.
    pub head: ServiceHead,
    /// The address to bind, `ip:port`.
    pub bind: AbiStr,
    /// The caller's buffer for the address bound.
    pub addr_buf: *mut u8,
    /// Its capacity: at least [`MAX_ADDR`].
    pub addr_cap: usize,
}

/// `io.read`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// The caller's buffer.
    pub buf: *mut u8,
    /// Its capacity.
    pub cap: usize,
}

/// `io.write`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WriteIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// The bytes.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
}
