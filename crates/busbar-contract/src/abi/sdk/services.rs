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
//! handle to read the stored answer. Nothing here allocates but [`Judged::within`] (the address
//! set an ESTABLISH takes): every result is a scalar or a view into the caller's own buffers.

use std::ffi::c_void;
use std::mem::size_of;
use std::task::Poll;

use crate::abi::host::conn::connector::WITHIN_SEPARATOR;
use crate::abi::host::service::{
    check_dest_judge, check_entitlement_check, check_random_fill, check_random_fill_in,
    check_records_claim, check_records_claim_in, check_records_get, check_records_list,
    check_trust_due, check_trust_sight, op, DestJudgeIn, EntitlementCheckIn, HostSlots, ItemSpan,
    RandomFillIn, RecordsClaimIn, RecordsGetIn, RecordsListIn, ServiceBufs, ServiceFn, ServiceHead,
    ServiceOut, TrustDueIn, TrustSightIn, CLAIM_WON, DEST_RESOLVE, ENTITLED, FOUND,
};
use crate::abi::mechanism::call::Span;
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

/// A service's answer that names things, one span's key each, as views into the caller's buffers,
/// every one checked present and UTF-8 before it is answered: `trust.due`'s counterparties due for
/// re-verification, and `dest.judge`'s judged addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Names<'b> {
    bytes: &'b [u8],
    spans: &'b [ItemSpan],
}

impl<'b> Names<'b> {
    /// How many names.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The names, in the host's order.
    pub fn names(&self) -> impl Iterator<Item = &'b str> + 'b {
        let bytes = self.bytes;
        self.spans.iter().filter_map(move |s| name(bytes, s))
    }
}

/// `dest.judge`'s answer: the `DEST_*` verdict, and, asked to resolve and admitted, every address
/// the host's one judgement judged (the first the one a dial pins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Judged<'b> {
    /// The `DEST_*` verdict; `DEST_ALLOWED` = admissible.
    pub verdict: u64,
    /// The addresses judged, as text; none unless asked to resolve and admitted.
    pub addresses: Names<'b>,
}

impl Judged<'_> {
    /// The addresses as the set an ESTABLISH's dial must land on (`EstablishIn::within`): so the
    /// judge, the caller's overlap check and the dial see one address set.
    #[must_use]
    pub fn within(&self) -> String {
        self.addresses
            .names()
            .collect::<Vec<_>>()
            .join(WITHIN_SEPARATOR)
    }
}

/// The counterparty span `s` names: its key, present and UTF-8.
fn name<'b>(bytes: &'b [u8], s: &ItemSpan) -> Option<&'b str> {
    std::str::from_utf8(present(bytes, s.key)?).ok()
}

/// The bytes `s` covers, when it is present.
fn present(bytes: &[u8], s: Span) -> Option<&[u8]> {
    if s.offset == SPAN_ABSENT {
        return None;
    }
    let at = s.offset as usize;
    bytes.get(at..at.checked_add(s.len as usize)?)
}

/// `records.list`'s answer: the caller's records, each a key and a value as views into the
/// caller's buffers, every one checked present before it is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Records<'b> {
    bytes: &'b [u8],
    spans: &'b [ItemSpan],
}

impl<'b> Records<'b> {
    /// The records as `(key, value)`, in key order.
    pub fn records(&self) -> impl Iterator<Item = (&'b [u8], &'b [u8])> + 'b {
        let bytes = self.bytes;
        self.spans
            .iter()
            .filter_map(move |s| Some((present(bytes, s.key)?, present(bytes, s.value)?)))
    }

    /// The key of the last record: the `after` that lists the next page.
    #[must_use]
    pub fn last_key(&self) -> Option<&'b [u8]> {
        present(self.bytes, self.spans.last()?.key)
    }
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
    /// dialing. Ready: the `DEST_*` verdict, `DEST_ALLOWED` = admissible. A refusal the name decides
    /// answers at once. With `resolve` (the caller's preallocated bytes and spans) the name is then
    /// resolved and every address judged; admitted, those addresses are written there and answered
    /// ([`Judged::within`] is the set an ESTABLISH lands within). Resolving may pend, so it is
    /// callable only from a ticketed op (on `Ticket::NONE` the host refuses it). A short answer is
    /// [`ServiceError::Short`]: re-call once, same handle, with the sizes it names.
    pub fn dest_judge<'b>(
        &self,
        handle: CompletionHandle,
        dest: &str,
        egress_class: u32,
        resolve: Option<(&'b mut [u8], &'b mut [ItemSpan])>,
    ) -> Pend<Judged<'b>> {
        let flags = if resolve.is_some() { DEST_RESOLVE } else { 0 };
        let (buf, spans): (&'b mut [u8], &'b mut [ItemSpan]) = resolve.unwrap_or_default();
        let input = DestJudgeIn {
            head: head::<DestJudgeIn>(op::DEST_JUDGE, handle),
            dest: text(dest),
            egress_class,
            flags,
            into: bufs(buf, spans),
        };
        let crossed = self.cross(op::DEST_JUDGE, |t| t.dest_judge, &input, check_dest_judge);
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(
            crossed
                .and_then(move |c| named(c, buf, spans))
                .map(|(out, addresses)| Judged {
                    verdict: out.value,
                    addresses,
                }),
        )
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
    ) -> Result<Names<'b>, ServiceError> {
        let input = TrustDueIn {
            head: head::<TrustDueIn>(op::TRUST_DUE, handle),
            into: bufs(buf, spans),
        };
        let crossed = self.cross(op::TRUST_DUE, |t| t.trust_due, &input, check_trust_due)?;
        named(crossed, buf, spans).map(|(_, due)| due)
    }

    /// `records.get`: the record `key` of the caller's own record `kind`, written into the caller's
    /// preallocated `buf`; reads see the instance's own queued writes. Ready: `Some` the record's
    /// value, or `None` when there is no such record (a tombstone reads absent). May pend (the
    /// kernel reads the store off the calling thread), so callable only from a ticketed op: on
    /// [`Poll::Pending`] re-issue the SAME handle to read the stored answer. A short `buf` is
    /// [`ServiceError::Short`]: re-call once, same handle, with the bytes it names.
    pub fn records_get<'b>(
        &self,
        handle: CompletionHandle,
        kind: &str,
        key: &[u8],
        buf: &'b mut [u8],
    ) -> Pend<Option<&'b [u8]>> {
        let mut span = [ItemSpan {
            key: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 0 },
        }];
        let input = RecordsGetIn {
            head: head::<RecordsGetIn>(op::RECORDS_GET, handle),
            kind: text(kind),
            key: raw(key),
            into: bufs(buf, &mut span),
        };
        let crossed = self.cross(
            op::RECORDS_GET,
            |t| t.records_get,
            &input,
            check_records_get,
        );
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let buf: &'b [u8] = buf;
        Poll::Ready(crossed.and_then(ready).and_then(|out| {
            if out.value != FOUND {
                return Ok(None);
            }
            // FOUND writes the record into span `0`; one without it broke the rule.
            let s = span.get(..out.items as usize).and_then(<[ItemSpan]>::first);
            s.and_then(|s| present(&buf[..out.len as usize], s.value))
                .map(Some)
                .ok_or(ServiceError::Broken)
        }))
    }

    /// `records.list`: the caller's own records of `kind` whose keys start with `prefix` (empty =
    /// every key), in key order after `after` (`None` = from the first), at most `limit` (`0` = as
    /// many as fit `MAX_SPANS`), written into the caller's preallocated `into` (bytes and spans).
    /// A tombstoned key is not listed. May pend, so callable only from a ticketed op; a short
    /// answer is [`ServiceError::Short`] (re-call once, same handle). A page's
    /// [`Records::last_key`] is the next page's `after`.
    pub fn records_list<'b>(
        &self,
        handle: CompletionHandle,
        kind: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
        (buf, spans): (&'b mut [u8], &'b mut [ItemSpan]),
    ) -> Pend<Records<'b>> {
        let input = RecordsListIn {
            head: head::<RecordsListIn>(op::RECORDS_LIST, handle),
            kind: text(kind),
            prefix: raw(prefix),
            after: after.map_or(NO_TEXT, raw),
            limit,
            _reserved: 0,
            into: bufs(buf, spans),
        };
        let crossed = self.cross(
            op::RECORDS_LIST,
            |t| t.records_list,
            &input,
            check_records_list,
        );
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(crossed.and_then(ready).and_then(|out| {
            // The service's check held `len` and `items` within the caps and every span inside
            // `len`.
            let records = Records {
                bytes: &buf[..out.len as usize],
                spans: &spans[..out.items as usize],
            };
            if records.records().count() == records.spans.len() {
                Ok(records)
            } else {
                Err(ServiceError::Broken)
            }
        }))
    }

    /// `records.claim`: claim `key` of the caller's own record `kind` once, for `ttl_ms`
    /// milliseconds: a put-if-absent, THE ONE path for approval redemption and replay refusal.
    /// Ready: `true` when this call won the claim, `false` when the key was already claimed. A
    /// claim with no time to live is REFUSED here, before the host is called (there is no
    /// default). May pend, so callable only from a ticketed op.
    pub fn records_claim(
        &self,
        handle: CompletionHandle,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
    ) -> Pend<bool> {
        let input = RecordsClaimIn {
            head: head::<RecordsClaimIn>(op::RECORDS_CLAIM, handle),
            kind: text(kind),
            key: raw(key),
            ttl_ms,
        };
        if check_records_claim_in(&input).is_err() {
            return Poll::Ready(Err(ServiceError::Declined(Outcome::Refused)));
        }
        verdict(self.cross(
            op::RECORDS_CLAIM,
            |t| t.records_claim,
            &input,
            check_records_claim,
        ))
        .map(|r| r.map(|v| v == CLAIM_WON))
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

/// The caller's `buf` and `spans`, lent to the host for one call.
fn bufs(buf: &mut [u8], spans: &mut [ItemSpan]) -> ServiceBufs {
    ServiceBufs {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
    }
}

/// A naming service's crossed answer over the caller's `buf` and `spans`: READY, its `out` and the
/// names it wrote; a short answer, [`ServiceError::Short`]; any other outcome declined. A name
/// absent or not UTF-8 is broken.
fn named<'b>(
    crossed: (Outcome, ServiceOut, Filled),
    buf: &'b [u8],
    spans: &'b [ItemSpan],
) -> Result<(ServiceOut, Names<'b>), ServiceError> {
    let out = ready(crossed)?;
    // The service's check held `len` and `items` within the caps and every span inside `len`.
    let names = Names {
        bytes: &buf[..out.len as usize],
        spans: &spans[..out.items as usize],
    };
    if names.names().count() != names.len() {
        return Err(ServiceError::Broken);
    }
    Ok((out, names))
}

/// A crossed answer that writes the caller's buffers: READY, its `out`; a short answer,
/// [`ServiceError::Short`]; any other outcome declined.
fn ready(
    (outcome, out, filled): (Outcome, ServiceOut, Filled),
) -> Result<ServiceOut, ServiceError> {
    match (outcome, filled) {
        (Outcome::Ready, _) => Ok(out),
        (Outcome::Failed, Filled::Short) => Err(ServiceError::Short {
            bytes: out.needed_bytes,
            items: out.needed_items,
        }),
        (other, _) => Err(ServiceError::Declined(other)),
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
    raw(s.as_bytes())
}

/// `b`, borrowed for the call.
const fn raw(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// An absent text: NULL, no length.
const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

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
