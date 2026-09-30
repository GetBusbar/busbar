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
    check_entitlement_check, op, EntitlementCheckIn, HostSlots, ServiceHead, ServiceOut, ENTITLED,
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
        // SAFETY: `table` is the host's live table, non-NULL by construction.
        let table = unsafe { &*self.table };
        if table.slots <= op::ENTITLEMENT_CHECK {
            return Err(ServiceError::Unserved);
        }
        let slot = table.entitlement_check.ok_or(ServiceError::Unserved)?;
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
        let mut out = ServiceOut {
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
        };
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
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
