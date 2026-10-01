// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, PLUGIN SIDE (`BUSBAR-1.6.0.md` THE DESIGN, host services; the plugin ABI: the
//! SDK's typed wrappers): safe calls into the [`HostSlots`] table the host handed an instance at
//! `open`, the one home of every host-service wrapper. The `unsafe` of a call through the table
//! (a raw frame, a raw `out`) stays here; a plugin crate calling these stays
//! `#![forbid(unsafe_code)]`. Every answer is judged by the service's own `check_*` before it is
//! read, so a host that answers outside the rules is a [`ServiceError::Broken`], never a value.
//!
//! A service that MAY PEND answers a [`Pend`]: [`Poll::Pending`] means the host holds the call on
//! the handle's ticket and wakes it; the op answers PENDING and, re-entered, re-issues the SAME
//! handle to read the stored answer. Nothing here allocates: every result is a scalar or a view
//! into the caller's own buffers.

use std::ffi::c_void;
use std::mem::size_of;
use std::task::Poll;

use crate::abi::host::service::{
    check_dest_judge, check_entitlement_check, check_random_fill, check_random_fill_in,
    check_trust_due, check_trust_sight, op, DestJudgeIn, EntitlementCheckIn, HostSlots, ItemSpan,
    RandomFillIn, ServiceBufs, ServiceFn, ServiceHead, ServiceOut, TrustDueIn, TrustSightIn,
    DEST_RESOLVE, ENTITLED,
};
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::check::{Fault, Filled, SPAN_ABSENT};
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
    /// The caller's buffers were short: re-call ONCE, on the same handle, with at least `bytes`
    /// bytes and `items` spans.
    Short {
        /// The bytes the answer needs.
        bytes: u64,
        /// The spans the answer needs.
        items: u64,
    },
}

/// The answer of a service that may pend.
pub type Pend<T> = Poll<Result<T, ServiceError>>;

/// `trust.due`'s answer: the counterparties due for re-verification, as views into the caller's
/// buffers, every one checked present and UTF-8 before it is answered.
#[derive(Debug, Clone, Copy)]
pub struct Due<'b> {
    bytes: &'b [u8],
    spans: &'b [ItemSpan],
}

impl<'b> Due<'b> {
    /// How many counterparties are due.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether none is due.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The counterparties, in the host's order.
    pub fn names(&self) -> impl Iterator<Item = &'b str> + 'b {
        let bytes = self.bytes;
        self.spans.iter().filter_map(move |s| name(bytes, s))
    }
}

/// The counterparty span `s` names: its key, present and UTF-8.
fn name<'b>(bytes: &'b [u8], s: &ItemSpan) -> Option<&'b str> {
    if s.key.offset == SPAN_ABSENT {
        return None;
    }
    let at = s.key.offset as usize;
    std::str::from_utf8(bytes.get(at..at.checked_add(s.key.len as usize)?)?).ok()
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
        let input = EntitlementCheckIn {
            head: head::<EntitlementCheckIn>(op::ENTITLEMENT_CHECK, handle),
            target: text(target),
        };
        let (outcome, out, _) = self.cross(
            op::ENTITLEMENT_CHECK,
            |t| t.entitlement_check,
            &input,
            check_entitlement_check,
        )?;
        match outcome {
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
        let input = RandomFillIn {
            head: head::<RandomFillIn>(op::RANDOM_FILL, handle),
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
        match self
            .cross(
                op::RANDOM_FILL,
                |t| t.random_fill,
                &input,
                check_random_fill,
            )?
            .0
        {
            Outcome::Ready => Ok(()),
            other => Err(ServiceError::Declined(other)),
        }
    }

    /// `dest.judge`: the host's ONE destination judge over `dest` (a URL or `host:port` named
    /// inside content) under egress class `egress_class` (`0` = the host's default), without
    /// dialing. Ready: a `DEST_*` verdict, `DEST_ALLOWED` = admissible. A refusal the name decides
    /// answers at once; with `resolve` the name is then resolved and the call may pend, so it is
    /// callable only from a ticketed op (on `Ticket::NONE` the host refuses it).
    pub fn dest_judge(
        &self,
        handle: CompletionHandle,
        dest: &str,
        egress_class: u32,
        resolve: bool,
    ) -> Pend<u64> {
        let input = DestJudgeIn {
            head: head::<DestJudgeIn>(op::DEST_JUDGE, handle),
            dest: text(dest),
            egress_class,
            flags: if resolve { DEST_RESOLVE } else { 0 },
        };
        verdict(self.cross(op::DEST_JUDGE, |t| t.dest_judge, &input, check_dest_judge))
    }

    /// `trust.sight`: report `counterparty`'s catalogue hash; the KERNEL judges it. Ready: a
    /// `TRUST_*` verdict (new, same, drifted, quarantined). May pend (the kernel writes a
    /// demotion or its clearing durably before it answers), so callable only from a ticketed op.
    pub fn trust_sight(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        catalogue_hash: &str,
    ) -> Pend<u64> {
        let input = TrustSightIn {
            head: head::<TrustSightIn>(op::TRUST_SIGHT, handle),
            counterparty: text(counterparty),
            catalogue_hash: text(catalogue_hash),
        };
        verdict(self.cross(
            op::TRUST_SIGHT,
            |t| t.trust_sight,
            &input,
            check_trust_sight,
        ))
    }

    /// `trust.due`: the counterparties the kernel's `tick` marked for re-verification, written
    /// into the caller's preallocated `buf` and `spans`. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Short`] when the buffers are short (re-call once, same handle); otherwise
    /// as every service: unserved, declined, or broken (a name absent or not UTF-8 is broken).
    pub fn trust_due<'b>(
        &self,
        handle: CompletionHandle,
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Result<Due<'b>, ServiceError> {
        let input = TrustDueIn {
            head: head::<TrustDueIn>(op::TRUST_DUE, handle),
            into: ServiceBufs {
                buf: buf.as_mut_ptr(),
                cap: buf.len(),
                spans: spans.as_mut_ptr(),
                spans_cap: spans.len(),
            },
        };
        let (outcome, out, filled) =
            self.cross(op::TRUST_DUE, |t| t.trust_due, &input, check_trust_due)?;
        match (outcome, filled) {
            (Outcome::Ready, _) => {}
            (Outcome::Failed, Filled::Short) => {
                return Err(ServiceError::Short {
                    bytes: out.needed_bytes,
                    items: out.needed_items,
                })
            }
            (other, _) => return Err(ServiceError::Declined(other)),
        }
        // `check_trust_due` held `len` and `items` within the caps and every span inside `len`.
        let (bytes, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        let due = Due {
            bytes: &bytes[..out.len as usize],
            spans: &spans[..out.items as usize],
        };
        if due.names().count() != due.len() {
            return Err(ServiceError::Broken);
        }
        Ok(due)
    }

    /// Call `service` through `pick`'s slot with `input`, and judge the answer by `check`: the
    /// outcome, the `out` and how it filled the caller's buffers.
    fn cross<I>(
        &self,
        service: u32,
        pick: fn(&HostSlots) -> Option<ServiceFn>,
        input: &I,
        check: fn(&I, RawOutcome, &ServiceOut) -> Result<Filled, Fault>,
    ) -> Result<(Outcome, ServiceOut, Filled), ServiceError> {
        let slot = self.slot(service, pick)?;
        let mut out = blank_out();
        let ret = slot(
            self.ctx,
            std::ptr::from_ref(input).cast::<c_void>(),
            &mut out,
        );
        let filled = check(input, ret, &out).map_err(|_| ServiceError::Broken)?;
        Ok((ret.outcome(), out, filled))
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

/// The head of an `I` for `service`, under `handle`.
const fn head<I>(service: u32, handle: CompletionHandle) -> ServiceHead {
    ServiceHead {
        size: size_of::<I>() as u32,
        op: service,
        handle,
    }
}

/// `s`, borrowed for the call.
const fn text(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A verdict service's answer: Ready its `value`, PENDING held on the ticket, else declined.
fn verdict(crossed: Result<(Outcome, ServiceOut, Filled), ServiceError>) -> Pend<u64> {
    Poll::Ready(match crossed {
        Ok((Outcome::Ready, out, _)) => Ok(out.value),
        Ok((Outcome::Pending, ..)) => return Poll::Pending,
        Ok((other, ..)) => Err(ServiceError::Declined(other)),
        Err(e) => Err(e),
    })
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
