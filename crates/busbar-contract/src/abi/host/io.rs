// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O TABLE, `io.*` (`BUSBAR-1.6.0.md` THE DESIGN, the connections section: "No

use crate::abi::mechanism::call::{AbiStr, Field};
use crate::abi::mechanism::check::{self, fault, Fault, Rule};

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

/// [`ReadyIn::dir`] / [`ShutIn::how`]: the read direction.
pub const DIR_READ: u32 = 1;
/// [`ReadyIn::dir`] / [`ShutIn::how`]: the write direction (for a stream still connecting, its
pub const DIR_WRITE: u32 = 2;
/// [`ShutIn::how`]: both directions.
pub const DIR_BOTH: u32 = DIR_READ | DIR_WRITE;

/// Whether a slot may answer PENDING, and so is callable only inside a ticketed op. `false` for an
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

/// `io.open`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenIn {
    /// The head.
    pub head: ServiceHead,
    /// The address: `ip:port`, or `unix:` and an absolute path.
    pub addr: AbiStr,
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

/// `io.accept`'s and `io.ends`'s `in`: a handle and the caller's buffer for an address.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AddrIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle (the listener, for `accept`).
    pub handle: u64,
    /// The caller's buffer for the far end's address.
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

/// `io.ready`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadyIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// [`DIR_READ`] | [`DIR_WRITE`].
    pub dir: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `io.shut`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ShutIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
    /// [`DIR_READ`] | [`DIR_WRITE`] | [`DIR_BOTH`].
    pub how: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `io.close`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HandleIn {
    /// The head.
    pub head: ServiceHead,
    /// The handle.
    pub handle: u64,
}

/// `io.spawn`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SpawnIn {
    /// The head.
    pub head: ServiceHead,
    /// The program's absolute path.
    pub program: AbiStr,
    /// Its arguments.
    pub args: *const AbiStr,
    /// How many.
    pub args_len: usize,
    /// Its WHOLE environment: nothing else is set.
    pub env: *const Field,
    /// How many.
    pub env_len: usize,
}

/// A direction a `ready` waits on: exactly one of [`DIR_READ`] and [`DIR_WRITE`].
pub const fn check_dir(dir: u32) -> Result<(), Fault> {
    match dir {
        DIR_READ | DIR_WRITE => Ok(()),
        _ => Err(fault(Rule::UnknownCode, "io.ready.dir")),
    }
}

/// What a `shut` shuts: [`DIR_READ`], [`DIR_WRITE`] or [`DIR_BOTH`].
pub const fn check_how(how: u32) -> Result<(), Fault> {
    match how {
        DIR_READ | DIR_WRITE | DIR_BOTH => Ok(()),
        _ => Err(fault(Rule::UnknownCode, "io.shut.how")),
    }
}

/// An address buffer: a capacity never comes with a NULL pointer, and it is at least
pub fn check_addr_buf(buf: *mut u8, cap: usize, field: &'static str) -> Result<(), Fault> {
    check::listed(buf.cast_const(), cap, field)?;
    if cap < MAX_ADDR || buf.is_null() {
        return Err(fault(Rule::OverCap, field));
    }
    Ok(())
}

/// A `spawn`'s lists: a count never comes with a NULL pointer.
pub fn check_spawn_in(i: &SpawnIn) -> Result<(), Fault> {
    check::text(i.program, "io.spawn.program")?;
    check::listed(i.args, i.args_len, "io.spawn.args")?;
    check::listed(i.env, i.env_len, "io.spawn.env")
}

#[cfg(test)]
#[path = "../tests/host_io_tests.rs"]
mod tests;
