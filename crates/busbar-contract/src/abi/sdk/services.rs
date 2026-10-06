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
    check_clock_now, check_dest_judge, check_entitlement_check, check_random_fill,
    check_random_fill_in, check_records_claim, check_records_claim_in, check_records_get,
    check_records_list, check_sign, check_trust_due, check_trust_serves, check_trust_sight,
    check_trust_sight_item, check_trust_state, check_trust_verify, check_unit_nest,
    check_work_find, check_work_open, check_work_resume, check_work_settle, op, ClockNowIn,
    ClockReading, DestJudgeIn, EntitlementCheckIn, HostSlots, ItemSpan, RandomFillIn,
    RecordsClaimIn, RecordsGetIn, RecordsListIn, ServiceBufs, ServiceFn, ServiceHead, ServiceOut,
    SignIn, TrustDueIn, TrustServesIn, TrustSightIn, TrustSightItemIn, TrustStateIn, TrustVerifyIn,
    UnitNestIn, WorkFindIn, WorkOpenIn, WorkResumeIn, WorkSettleIn, ABSENT, CLAIM_WON,
    DEST_ALLOWED, DEST_RESOLVE, ENTITLED, FOUND, TRUST_REACHED, TRUST_UNREACHABLE,
};
use crate::abi::mechanism::call::{
    AbiStr, Blob, Outcome, RawOutcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use crate::abi::mechanism::check::{Fault, Filled, SPAN_ABSENT};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket, WakeFn};

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

impl<'b> Judged<'b> {
    /// What decided a refusal the caller asked explained (`DEST_EXPLAIN`): the refused address,
    /// or the resolver's reason; `None` on admission or when the name alone decided it.
    #[must_use]
    pub fn detail(&self) -> Option<&'b str> {
        if self.verdict == DEST_ALLOWED {
            return None;
        }
        self.addresses.names().next()
    }

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

/// The value span `s` carries: present, inside `bytes`.
fn value<'b>(bytes: &'b [u8], s: &ItemSpan) -> Option<&'b [u8]> {
    if s.value.offset == SPAN_ABSENT {
        return None;
    }
    let at = s.value.offset as usize;
    bytes.get(at..at.checked_add(s.value.len as usize)?)
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

/// `trust.state`'s answer: the counterparty's `KEY_*` state, and its items, in item order.
#[derive(Debug, Clone, Copy)]
pub struct TrustItems<'b> {
    /// The counterparty's `KEY_*` state.
    pub state: u64,
    bytes: &'b [u8],
    spans: &'b [ItemSpan],
}

/// One item of [`TrustItems`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustItem<'b> {
    /// The item.
    pub item: &'b str,
    /// Its state word: `new`, `same`, `drifted`, `quarantined` or `approved`.
    pub state: &'b str,
    /// The digest it is approved at; `None` = none.
    pub approved: Option<&'b str>,
    /// The digest it was last sighted at; `None` = never.
    pub seen: Option<&'b str>,
}

impl<'b> TrustItems<'b> {
    /// The items, in item order.
    pub fn items(&self) -> impl Iterator<Item = TrustItem<'b>> + 'b {
        let bytes = self.bytes;
        self.spans.iter().filter_map(move |s| {
            let item = name(bytes, s)?;
            let value = std::str::from_utf8(present(bytes, s.value)?).ok()?;
            let mut parts = value.splitn(3, '\0');
            let (state, approved, seen) = (parts.next()?, parts.next()?, parts.next()?);
            let some = |s: &'b str| (!s.is_empty()).then_some(s);
            Some(TrustItem {
                item,
                state,
                approved: some(approved),
                seen: some(seen),
            })
        })
    }
}

/// THE HOST'S WAKE, as `open` handed it (`HostTables::wake`): an instance holding work of its own
/// (a plane's session output, named on its driver ticket) wakes a ticket through it, from any
/// thread. A wake never blocks and never fails; one for a stale ticket is dropped by the host.
#[derive(Debug, Clone, Copy)]
pub struct Wake {
    ctx: HostCtx,
    wake: WakeFn,
}

// SAFETY: the context is the host's per-instance state and the wake a plain code address; the
// mechanism states the wake callable from any thread for the instance's life.
unsafe impl Send for Wake {}
// SAFETY: as above.
unsafe impl Sync for Wake {}

impl Wake {
    /// The wake in the tables `open` handed the instance; `None` when the host handed none.
    #[must_use]
    pub fn of(tables: &HostTables) -> Option<Self> {
        tables.wake.map(|wake| Self {
            ctx: tables.ctx,
            wake,
        })
    }

    /// Wake `ticket`.
    pub fn wake(&self, ticket: Ticket) {
        (self.wake)(self.ctx, ticket);
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

    /// `clock.now`: the kernel's one clock, wall and monotonic, so a plugin reads no clock of its
    /// own and a test or the oracle controls its time. `handle` is the op's own completion handle.
    /// Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError`]: the host serves no `clock.now`, declined it, or broke its rules.
    pub fn clock_now(&self, handle: CompletionHandle) -> Result<ClockReading, ServiceError> {
        let mut reading = ClockReading {
            size: size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 0,
            mono_ns: 0,
        };
        let input = ClockNowIn {
            head: head::<ClockNowIn>(op::CLOCK_NOW, handle),
            reading: std::ptr::from_mut(&mut reading),
        };
        match self
            .cross(op::CLOCK_NOW, |t| t.clock_now, &input, check_clock_now)?
            .0
        {
            Outcome::Ready => Ok(reading),
            other => Err(ServiceError::Declined(other)),
        }
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
        self.dest_judge_as(handle, dest, egress_class, 0, resolve)
    }

    /// [`Self::dest_judge`] with the caller's further `flags` (`DEST_REFUSE_PRIVATE`,
    /// `DEST_EXPLAIN`; `DEST_RESOLVE` follows `resolve`): asked to explain, a refusal an address
    /// or the resolution decided names it ([`Judged::detail`]).
    pub fn dest_judge_as<'b>(
        &self,
        handle: CompletionHandle,
        dest: &str,
        egress_class: u32,
        flags: u32,
        resolve: Option<(&'b mut [u8], &'b mut [ItemSpan])>,
    ) -> Pend<Judged<'b>> {
        let flags = (flags & !DEST_RESOLVE) | if resolve.is_some() { DEST_RESOLVE } else { 0 };
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
        self.sighting(handle, counterparty, catalogue_hash, TRUST_REACHED)
    }

    /// `trust.sight` with [`TRUST_UNREACHABLE`]: the plane could NOT reach `counterparty` to look.
    /// Ready: the KERNEL's last `TRUST_*` verdict, nothing changed; the plane fails its call as an
    /// upstream failure. Never drifts, never clears, never quarantines.
    ///
    /// # Errors
    ///
    /// As [`Self::trust_sight`].
    pub fn trust_unreachable(&self, handle: CompletionHandle, counterparty: &str) -> Pend<u64> {
        self.sighting(handle, counterparty, "", TRUST_UNREACHABLE)
    }

    fn sighting(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        catalogue_hash: &str,
        outcome: u32,
    ) -> Pend<u64> {
        let input = TrustSightIn {
            head: head::<TrustSightIn>(op::TRUST_SIGHT, handle),
            counterparty: text(counterparty),
            catalogue_hash: text(catalogue_hash),
            outcome,
            _outcome_reserved: 0,
        };
        verdict(self.cross(
            op::TRUST_SIGHT,
            |t| t.trust_sight,
            &input,
            check_trust_sight,
        ))
    }

    /// `trust.sight_item`: report the digest ONE ITEM of `counterparty` is offered at now (the
    /// plane's live re-fetch); the KERNEL records it. Ready: a `TRUST_*` sighting verdict. Never
    /// pends.
    ///
    /// # Errors
    ///
    /// As every service: unserved, declined, or broken.
    pub fn trust_sight_item(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Result<u64, ServiceError> {
        let input = TrustSightItemIn {
            head: head::<TrustSightItemIn>(op::TRUST_SIGHT_ITEM, handle),
            counterparty: text(counterparty),
            item: text(item),
            digest: text(digest),
        };
        let crossed = self.cross(
            op::TRUST_SIGHT_ITEM,
            |t| t.trust_sight_item,
            &input,
            check_trust_sight_item,
        )?;
        Ok(ready(crossed)?.value)
    }

    /// `trust.serves`: THE KERNEL'S APPROVE as a query, for a route leg after its live re-fetch:
    /// whether `counterparty` serves `item` (`None` = as a whole) at `digest` (`None` = its last
    /// sighting). Ready: `DISTRUST_NONE`, or the `DISTRUST_*` that refuses it (an unknown item
    /// apart from a known one ungranted). Never pends.
    ///
    /// # Errors
    ///
    /// As every service: unserved, declined, or broken.
    pub fn trust_serves(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Result<u64, ServiceError> {
        let input = TrustServesIn {
            head: head::<TrustServesIn>(op::TRUST_SERVES, handle),
            counterparty: text(counterparty),
            item: text(item.unwrap_or("")),
            digest: text(digest.unwrap_or("")),
        };
        let crossed = self.cross(
            op::TRUST_SERVES,
            |t| t.trust_serves,
            &input,
            check_trust_serves,
        )?;
        Ok(ready(crossed)?.value)
    }

    /// `trust.state`: the KERNEL'S TRUST STATE of `counterparty` and its items, as the core-admin
    /// `GET /api/v1/admin/trust` lists them, for the plane's own administrative views; written into
    /// the caller's preallocated `buf` and `spans`. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Short`] when the buffers are short (re-call once, same handle); otherwise
    /// as every service: unserved, declined (an undeclared counterparty), or broken.
    pub fn trust_state<'b>(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Result<TrustItems<'b>, ServiceError> {
        let input = TrustStateIn {
            head: head::<TrustStateIn>(op::TRUST_STATE, handle),
            counterparty: text(counterparty),
            into: bufs(buf, spans),
        };
        let crossed = self.cross(
            op::TRUST_STATE,
            |t| t.trust_state,
            &input,
            check_trust_state,
        )?;
        let out = ready(crossed)?;
        let items = TrustItems {
            state: out.value,
            bytes: &buf[..out.len as usize],
            spans: &spans[..out.items as usize],
        };
        if items.items().count() != items.spans.len() {
            return Err(ServiceError::Broken);
        }
        Ok(items)
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

    /// `trust.verify`: verify `signatures` (the document's signature list as written, one JSON
    /// array; empty = none) over `payload` against the root key the kernel holds for
    /// `counterparty`; the KERNEL judges. Ready: the `SIGNED_*` verdict and, for
    /// `SIGNED_ALGORITHM` / `SIGNED_CRITICAL`, the name it refused, written into the caller's
    /// preallocated `buf`. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Short`] when `buf` is short (re-call once, same handle); otherwise as every
    /// service: unserved, declined, or broken (a name that is not UTF-8 is broken).
    pub fn trust_verify<'b>(
        &self,
        handle: CompletionHandle,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
        buf: &'b mut [u8],
    ) -> Result<Signed<'b>, ServiceError> {
        let input = TrustVerifyIn {
            head: head::<TrustVerifyIn>(op::TRUST_VERIFY, handle),
            counterparty: text(counterparty),
            payload: blob(payload, BLOB_OCTETS),
            signatures: blob(signatures, BLOB_JSON),
            into: bufs(buf, &mut []),
        };
        let crossed = self.cross(
            op::TRUST_VERIFY,
            |t| t.trust_verify,
            &input,
            check_trust_verify,
        )?;
        let out = ready(crossed)?;
        let buf: &'b [u8] = buf;
        let named =
            std::str::from_utf8(&buf[..out.len as usize]).map_err(|_| ServiceError::Broken)?;
        Ok(Signed {
            verdict: out.value,
            named,
        })
    }

    /// `sign`: sign `data` with busbar's key under the plugin's declared signing domain and key-id
    /// prefix (the host refuses a plugin that declares none). Ready: span `0`, the key id (UTF-8)
    /// and the signature, written into the caller's preallocated `buf` and `spans`. Never pends.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Short`] when the buffers are short (re-call once, same handle); otherwise
    /// as every service: unserved, declined, or broken (no span, a key id absent or not UTF-8, or
    /// a signature absent is broken).
    pub fn sign<'b>(
        &self,
        handle: CompletionHandle,
        data: &[u8],
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Result<Signature<'b>, ServiceError> {
        let input = SignIn {
            head: head::<SignIn>(op::SIGN, handle),
            data: blob(data, BLOB_OCTETS),
            into: bufs(buf, spans),
        };
        let out = ready(self.cross(op::SIGN, |t| t.sign, &input, check_sign)?)?;
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        // The service's check held `len` and `items` within the caps and every span inside `len`.
        let (bytes, spans) = (&buf[..out.len as usize], &spans[..out.items as usize]);
        let first = spans.first().ok_or(ServiceError::Broken)?;
        let key_id = name(bytes, first).ok_or(ServiceError::Broken)?;
        let signature = value(bytes, first).ok_or(ServiceError::Broken)?;
        Ok(Signature { key_id, signature })
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

    /// `work.open`: open a durable work handle of `kind` (one of the plugin's record kinds) for the
    /// principal of the unit the op serves, with `record` (at most `MAX_WORK_RECORD` bytes). Ready:
    /// the handle and its reference, written into the caller's preallocated `buf` (at least
    /// `WORK_REFERENCE_LEN` bytes) and `spans` (at least one). May pend.
    pub fn work_open<'b>(
        &self,
        handle: CompletionHandle,
        kind: &str,
        record: &[u8],
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Pend<Opened<'b>> {
        let input = WorkOpenIn {
            head: head::<WorkOpenIn>(op::WORK_OPEN, handle),
            kind: text(kind),
            record: blob(record, BLOB_OCTETS),
            into: bufs(buf, spans),
        };
        let crossed = self.cross(op::WORK_OPEN, |t| t.work_open, &input, check_work_open);
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(crossed.and_then(move |c| {
            let (out, names) = named(c, buf, spans)?;
            let reference = names.names().next().ok_or(ServiceError::Broken)?;
            Ok(Opened {
                handle: out.value,
                reference,
            })
        }))
    }

    /// `work.find`: the handle `reference` names, within this instance and the principal of the
    /// unit the op serves. Ready `None` for every denial alike; found, the handle, its state byte
    /// and its record, a view into the caller's `buf`. May pend.
    pub fn work_find<'b>(
        &self,
        handle: CompletionHandle,
        reference: &str,
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Pend<Option<Found<'b>>> {
        let input = WorkFindIn {
            head: head::<WorkFindIn>(op::WORK_FIND, handle),
            reference: text(reference),
            into: bufs(buf, spans),
        };
        let crossed = self.cross(op::WORK_FIND, |t| t.work_find, &input, check_work_find);
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(crossed.and_then(move |c| {
            let out = ready(c)?;
            if out.value == ABSENT {
                return Ok(None);
            }
            found(&out, buf, spans).map(Some)
        }))
    }

    /// `work.settle`: settle this instance's live handle `work` with its final `record`. May pend.
    pub fn work_settle(&self, handle: CompletionHandle, work: u64, record: &[u8]) -> Pend<()> {
        let input = WorkSettleIn {
            head: head::<WorkSettleIn>(op::WORK_SETTLE, handle),
            handle: work,
            record: blob(record, BLOB_OCTETS),
        };
        match verdict(self.cross(
            op::WORK_SETTLE,
            |t| t.work_settle,
            &input,
            check_work_settle,
        )) {
            Poll::Ready(r) => Poll::Ready(r.map(|_| ())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// `work.resume`: bind this instance's handle `work` to the unit the op serves (a continuation,
    /// of the principal the handle recorded). Ready: its state byte and record, a view into the
    /// caller's `buf`. May pend.
    pub fn work_resume<'b>(
        &self,
        handle: CompletionHandle,
        work: u64,
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Pend<Found<'b>> {
        let input = WorkResumeIn {
            head: head::<WorkResumeIn>(op::WORK_RESUME, handle),
            handle: work,
            into: bufs(buf, spans),
        };
        let crossed = self.cross(
            op::WORK_RESUME,
            |t| t.work_resume,
            &input,
            check_work_resume,
        );
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(crossed.and_then(move |c| {
            let out = ready(c)?;
            found(&out, buf, spans).map(|f| Found { handle: work, ..f })
        }))
    }

    /// `unit.nest`: run a nested unit on whatever serves the claim `verb` `target` names, as a
    /// child of the unit the op serves (its principal, its scope, its admission chain), with
    /// `body`. Ready: the child's whole reply, a view into the caller's preallocated `buf` and
    /// `spans` (at least one, plus one per head field it keeps). May pend; a short answer is
    /// [`ServiceError::Short`]: re-call once, same handle, with the sizes it names.
    pub fn unit_nest<'b>(
        &self,
        handle: CompletionHandle,
        verb: &str,
        target: &str,
        body: &[u8],
        buf: &'b mut [u8],
        spans: &'b mut [ItemSpan],
    ) -> Pend<Nested<'b>> {
        let input = UnitNestIn {
            head: head::<UnitNestIn>(op::UNIT_NEST, handle),
            verb: text(verb),
            target: text(target),
            body: blob(body, BLOB_OCTETS),
            into: bufs(buf, spans),
        };
        let crossed = self.cross(op::UNIT_NEST, |t| t.unit_nest, &input, check_unit_nest);
        if let Ok((Outcome::Pending, ..)) = crossed {
            return Poll::Pending;
        }
        let (buf, spans): (&'b [u8], &'b [ItemSpan]) = (buf, spans);
        Poll::Ready(crossed.and_then(move |c| {
            let out = ready(c)?;
            let bytes = &buf[..out.len as usize];
            let spans = &spans[..out.items as usize];
            let (first, fields) = spans.split_first().ok_or(ServiceError::Broken)?;
            let at = first.value.offset as usize;
            let body = bytes
                .get(at..at.saturating_add(first.value.len as usize))
                .filter(|_| first.value.offset != SPAN_ABSENT)
                .ok_or(ServiceError::Broken)?;
            Ok(Nested {
                status: out.value,
                body,
                bytes,
                fields,
            })
        }))
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

/// `b`, borrowed for the call, in format `fmt`.
const fn blob(b: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags: 0,
    }
}

/// What `unit.nest` answered: the child's status, body and head fields, views into the caller's
/// buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nested<'b> {
    /// The child's status.
    pub status: u64,
    /// The child's body.
    pub body: &'b [u8],
    bytes: &'b [u8],
    fields: &'b [ItemSpan],
}

impl<'b> Nested<'b> {
    /// The child's head fields, name and value, in its order.
    pub fn fields(&self) -> impl Iterator<Item = (&'b [u8], &'b [u8])> + 'b {
        let bytes = self.bytes;
        self.fields.iter().filter_map(move |s| {
            let range =
                |o: u32, n: u32| bytes.get(o as usize..(o as usize).checked_add(n as usize)?);
            Some((
                range(s.key.offset, s.key.len)?,
                range(s.value.offset, s.value.len)?,
            ))
        })
    }
}

/// What `work.open` answered: the handle, and its reference, a view into the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened<'b> {
    /// The handle the plugin calls with.
    pub handle: u64,
    /// The reference the plugin hands its caller.
    pub reference: &'b str,
}

/// What `work.find` or `work.resume` answered: the handle, its state byte (`WORK_LIVE` /
/// `WORK_SETTLED`) and its record, a view into the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found<'b> {
    /// The handle.
    pub handle: u64,
    /// `WORK_LIVE` or `WORK_SETTLED`.
    pub state: u8,
    /// The record.
    pub record: &'b [u8],
}

/// A found handle's answer over the caller's `buf` and `spans`: span `0`'s one-byte key is the
/// state, its value the record; anything else is broken.
fn found<'b>(
    out: &ServiceOut,
    buf: &'b [u8],
    spans: &'b [ItemSpan],
) -> Result<Found<'b>, ServiceError> {
    let bytes = &buf[..out.len as usize];
    let s = spans
        .get(..out.items as usize)
        .and_then(<[ItemSpan]>::first)
        .ok_or(ServiceError::Broken)?;
    let range = |offset: u32, len: u32| {
        (offset != SPAN_ABSENT)
            .then(|| bytes.get(offset as usize..(offset as usize).checked_add(len as usize)?))
            .flatten()
    };
    let state = match range(s.key.offset, s.key.len) {
        Some([state]) => *state,
        _ => return Err(ServiceError::Broken),
    };
    let record = range(s.value.offset, s.value.len).ok_or(ServiceError::Broken)?;
    Ok(Found {
        handle: out.value,
        state,
        record,
    })
}

/// What `trust.verify` answered: the verdict, and the name a `SIGNED_ALGORITHM` /
/// `SIGNED_CRITICAL` verdict refused (empty for every other verdict), a view into the caller's
/// buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<'b> {
    /// The `SIGNED_*` verdict.
    pub verdict: u64,
    /// The refused algorithm or critical member.
    pub named: &'b str,
}

/// What `sign` answered: the key id the signature verifies under and the signature, views into
/// the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature<'b> {
    /// The key id (busbar's key id under the plugin's declared prefix).
    pub key_id: &'b str,
    /// The signature bytes.
    pub signature: &'b [u8],
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
