// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIFECYCLE: the slot set every kind's table leads with ([`OpsHead`]), and the `in`/`out` of

use super::call::{Op, OutHead};

/// [`InHead::op`] of each lifecycle slot, in table order. A kind's own ops number on from
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
    /// `ready`: the door's optional tail op ([`super::super::door::Door::ready`]), NOT a table
    pub const READY: u32 = u32::MAX;
    /// `migrate`: the door's optional tail op ([`super::super::door::Door::migrate`]), NOT a table
    pub const MIGRATE: u32 = u32::MAX - 1;
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
    /// Reload with the new config; may pend. In [`RefreshIn`], out [`OutHead`].
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

/// `open`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenOut {
    /// The head.
    pub head: OutHead,
    /// The instance every later call is made on.
    pub instance: *mut std::os::raw::c_void,
    /// For an `open` that did not answer READY: how many bytes of [`OpenIn::err_buf`] its reason
    /// fills; `0` = none. More than [`OpenIn::err_cap`] is a malformed answer (FAULT).
    pub err_len: usize,
}

/// `tick`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TickOut {
    /// The head.
    pub head: OutHead,
    /// When to tick next; `0` = no tick scheduled until the next wake of the instance's driver
    /// ticket (R-PUSH): a wake runs `drive` and then re-polls `tick`, so `0` is not "never".
    pub next_tick_ns: u64,
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
