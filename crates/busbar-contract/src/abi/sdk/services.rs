// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, PLUGIN SIDE (`BUSBAR-1.6.0.md` THE DESIGN, host services; the plugin ABI: the
//! SDK's typed wrappers): safe calls into the [`HostSlots`] table the host handed an instance at
//! `open`, the one home of every host-service wrapper. The `unsafe` of a call through the table
//! (a raw frame, a raw `out`) stays here; a plugin crate calling these stays
//! `#![forbid(unsafe_code)]`. Every answer is judged by the service's own `check_*` before it is
//! read, so a host that answers outside the rules is a [`ServiceError::Broken`], never a value.

use std::ffi::c_void;
use std::mem::size_of;

use crate::abi::host::service::{
    check_entitlement_check, check_random_fill, check_random_fill_in, op, EntitlementCheckIn,
    HostSlots, RandomFillIn, ServiceBufs, ServiceFn, ServiceHead, ServiceOut, ENTITLED,
};
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables};

/// Why a service call has no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// The host serves no such service.
    Unserved,
    /// The host refused or failed the call.
    Declined(Outcome),
    /// The host's answer broke the service's rules.
    Broken,
}

/// The host services an instance was opened with: its context and the table.
#[derive(Debug, Clone, Copy)]
pub struct Services {
    ctx: HostCtx,
    table: *const HostSlots,
}

// SAFETY: the table is the host's static and the context the host's leaked per-instance state; the
// host states both are callable from any thread for the instance's life.
unsafe impl Send for Services {}
// SAFETY: as above.
unsafe impl Sync for Services {}

impl Services {
    /// The services in the tables `open` handed the instance; `None` when the host offers none.
    #[must_use]
    pub fn of(tables: &HostTables) -> Option<Self> {
        (!tables.services.is_null()).then_some(Self {
            ctx: tables.ctx,
            table: tables.services,
        })
    }

    /// `entitlement.check`: whether the unit the calling op serves is entitled to `target`,
    /// `"<scope_kind>:<name>"`. `handle` is the op's own completion handle. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError`]: the host serves no `entitlement.check`, declined it, or broke its rules.
    pub fn entitled(&self, handle: CompletionHandle, target: &str) -> Result<bool, ServiceError> {
        let slot = self.slot(op::ENTITLEMENT_CHECK, |t| t.entitlement_check)?;
        let input = EntitlementCheckIn {
            head: ServiceHead {
                size: size_of::<EntitlementCheckIn>() as u32,
                op: op::ENTITLEMENT_CHECK,
                handle,
            },
            target: AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
        };
        let mut out = blank_out();
        let ret = slot(
            self.ctx,
            std::ptr::from_ref(&input).cast::<c_void>(),
            &mut out,
        );
        check_entitlement_check(&input, ret, &out).map_err(|_| ServiceError::Broken)?;
        match ret.outcome() {
            Outcome::Ready => Ok(out.value == ENTITLED),
            other => Err(ServiceError::Declined(other)),
        }
    }

    /// `random.fill`: fill `buf` from the kernel's CSPRNG. `buf` holds 1 to `MAX_RANDOM_FILL`
    /// bytes; any other length is REFUSED here, before the host is called. `handle` is the op's
    /// own completion handle. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError`]: the host serves no `random.fill`, it or this wrapper declined it, or the
    /// host broke its rules.
    pub fn random_fill(
        &self,
        handle: CompletionHandle,
        buf: &mut [u8],
    ) -> Result<(), ServiceError> {
        let slot = self.slot(op::RANDOM_FILL, |t| t.random_fill)?;
        let input = RandomFillIn {
            head: ServiceHead {
                size: size_of::<RandomFillIn>() as u32,
                op: op::RANDOM_FILL,
                handle,
            },
            len: buf.len() as u64,
            into: ServiceBufs {
                buf: buf.as_mut_ptr(),
                cap: buf.len(),
                spans: std::ptr::null_mut(),
                spans_cap: 0,
            },
        };
        if check_random_fill_in(&input).is_err() {
            return Err(ServiceError::Declined(Outcome::Refused));
        }
        let mut out = blank_out();
        let ret = slot(
            self.ctx,
            std::ptr::from_ref(&input).cast::<c_void>(),
            &mut out,
        );
        check_random_fill(&input, ret, &out).map_err(|_| ServiceError::Broken)?;
        match ret.outcome() {
            Outcome::Ready => Ok(()),
            other => Err(ServiceError::Declined(other)),
        }
    }

    /// The host's slot for `service`, read only when the host's table is long enough to hold it.
    fn slot(
        &self,
        service: u32,
        pick: fn(&HostSlots) -> Option<ServiceFn>,
    ) -> Result<ServiceFn, ServiceError> {
        // SAFETY: `table` is the host's live table, non-NULL by construction.
        let table = unsafe { &*self.table };
        if table.slots <= service {
            return Err(ServiceError::Unserved);
        }
        pick(table).ok_or(ServiceError::Unserved)
    }
}

/// An `out` for the host to answer into; FAULT until it does.
fn blank_out() -> ServiceOut {
    ServiceOut {
        size: size_of::<ServiceOut>() as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        value: 0,
        len: 0,
        items: 0,
        needed_bytes: 0,
        needed_items: 0,
        error: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
    }
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
