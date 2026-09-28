// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND: `abi/auth/`. Four kind ops are checked by their own validators:
//!
//! * `verify` by `check_identify`, over the host's `IdentityBuf` from `VerifyIn::out_buf`;
//! * `complete_login` by `check_complete_login`, over the host's `IdentityBuf` from
//!   `CompleteLoginIn::out_buf`;
//! * `fields` by `check_fields`, over the host's field buffer and array from `FieldsIn`;
//! * `begin_login` by `check_begin_login` (its URL and form are plugin memory under the lease, so
//!   no host capacity is involved).
//!
//! `open_outbound` and `outbound_ready` state no rule beyond the mechanism's and answer `Ok`, as
//! does every lifecycle slot.
//!
//! The group spans (`verify`, `complete_login`) and the field spans (`fields`) the plugin reports
//! are built through `check::reported` with the capacity the host passed in the op's `in`, so a
//! count above it is FAULT before any slice exists (the HOST DUTY `abi/auth/check.rs` states).
//! They are built only when the validator reads them: a READY identity verdict, or a READY
//! `fields` answer. Every other answer's count is not part of the answer and is never read.
//!
//! `verify`, `complete_login` and `fields` have a short-buffer path: FAILED with a non-zero
//! `needed_*` (`IdentifyOut`, `FieldsOut`).
//!
//! The timeout outcome is FAILED: `abi/auth/mod.rs` states that deadlines are host-owned and the
//! host calls `cancel` at expiry, and names no other outcome for an expired op.

use busbar_contract::abi::auth::{
    self, check_begin_login, check_complete_login, check_fields, check_identify, slot,
    BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut, IdentifyOut,
    IdentityBuf, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, Span,
    VerifyIn, LOGIN_IDENTITY, VERDICT_IDENTITY,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The auth kind.
#[derive(Debug, Clone, Copy)]
pub struct Auth;

// SAFETY: `#[repr(C)]` in `abi/auth/`, each leading with its head, plain data whose pointers are
// host buffers or plugin memory held under the lease; host buffers only.
unsafe impl InFrame for VerifyIn {}
unsafe impl InFrame for BeginLoginIn {}
unsafe impl InFrame for CompleteLoginIn {}
unsafe impl InFrame for OpenOutboundIn {}
unsafe impl InFrame for OutboundReadyIn {}
unsafe impl InFrame for FieldsIn {}
unsafe impl OutFrame for IdentifyOut {}
unsafe impl OutFrame for BeginLoginOut {}
unsafe impl OutFrame for OpenOutboundOut {}
unsafe impl OutFrame for OutboundReadyOut {}
unsafe impl OutFrame for FieldsOut {}

/// The rule each auth [`auth::Fault`] breaks.
const fn rule(f: auth::Fault) -> Rule {
    match f {
        auth::Fault::Vocabulary | auth::Fault::UnknownFlags => Rule::UnknownCode,
        auth::Fault::NotExactlyOne => Rule::NotExactlyOne,
        auth::Fault::NeededOnReady | auth::Fault::NeededNotFailed => Rule::NeededNotFailed,
        auth::Fault::NeededTooLarge => Rule::OverMax,
        auth::Fault::NeededWithinCap => Rule::WastedRecall,
        auth::Fault::AbsentWithLen => Rule::SpanNotAbsent,
        auth::Fault::SpanOutOfBounds => Rule::SpanOutOfBounds,
        auth::Fault::CountOverCap => Rule::OverCap,
        auth::Fault::CountMismatch => Rule::Contradiction,
        auth::Fault::NullWithCount => Rule::NullWithCount,
        auth::Fault::Missing => Rule::Missing,
    }
}

/// `fn $name(auth::Fault) -> Fault`: the shared fault of op `$op`, its field `$op.<variant>`.
macro_rules! op_fault {
    ($name:ident, $op:literal) => {
        /// The shared [`Fault`] for this op's [`auth::Fault`]: its [`rule`], and a field naming
        /// the op and the variant.
        const fn $name(f: auth::Fault) -> Fault {
            let field = match f {
                auth::Fault::Vocabulary => concat!($op, ".vocabulary"),
                auth::Fault::NotExactlyOne => concat!($op, ".not_exactly_one"),
                auth::Fault::NeededOnReady => concat!($op, ".needed_on_ready"),
                auth::Fault::NeededNotFailed => concat!($op, ".needed_not_failed"),
                auth::Fault::NeededTooLarge => concat!($op, ".needed_too_large"),
                auth::Fault::NeededWithinCap => concat!($op, ".needed_within_cap"),
                auth::Fault::AbsentWithLen => concat!($op, ".absent_with_len"),
                auth::Fault::SpanOutOfBounds => concat!($op, ".span_out_of_bounds"),
                auth::Fault::CountOverCap => concat!($op, ".count_over_cap"),
                auth::Fault::CountMismatch => concat!($op, ".count_mismatch"),
                auth::Fault::NullWithCount => concat!($op, ".null_with_count"),
                auth::Fault::UnknownFlags => concat!($op, ".unknown_flags"),
                auth::Fault::Missing => concat!($op, ".missing"),
            };
            fault(rule(f), field)
        }
    };
}

op_fault!(verify_fault, "verify");
op_fault!(complete_login_fault, "complete_login");
op_fault!(fields_fault, "fields");
op_fault!(begin_login_fault, "begin_login");

/// The group spans an identity answer reports: `out.identity.groups_len` of the host's
/// `buf.groups`, the count checked against `buf.groups_cap` first. Empty unless the answer is a
/// READY `identified` verdict, the one answer whose groups the validator reads.
fn groups<'a>(
    a: &Answer,
    out: &IdentifyOut,
    buf: &'a IdentityBuf,
    identified: u32,
    field: &'static str,
) -> Result<&'a [Span], Fault> {
    if a.outcome != Outcome::Ready || out.verdict != identified {
        return Ok(&[]);
    }
    // SAFETY: `buf` is the host's own `IdentityBuf` from the op's `in`, its `groups` an array of
    // `groups_cap` live spans the host allocated; `reported` refuses a count above that cap
    // before it builds the slice.
    unsafe {
        reported(
            buf.groups.cast_const(),
            u64::from(out.identity.groups_len),
            u64::from(buf.groups_cap),
            field,
        )
    }
}

impl Kind for Auth {
    const CODE: KindCode = KindCode::Auth;
    type Ops = auth::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::VERIFY => "verify",
            slot::BEGIN_LOGIN => "begin_login",
            slot::COMPLETE_LOGIN => "complete_login",
            slot::OPEN_OUTBOUND => "open_outbound",
            slot::OUTBOUND_READY => "outbound_ready",
            slot::FIELDS => "fields",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::VERIFY => {
                let buf = &a.input::<VerifyIn>()?.out_buf;
                let out = a.out::<IdentifyOut>()?;
                let groups = groups(a, out, buf, VERDICT_IDENTITY, "verify.groups")?;
                check_identify(a.outcome, out, buf, groups).map_err(verify_fault)
            }
            slot::COMPLETE_LOGIN => {
                let buf = &a.input::<CompleteLoginIn>()?.out_buf;
                let out = a.out::<IdentifyOut>()?;
                let groups = groups(a, out, buf, LOGIN_IDENTITY, "complete_login.groups")?;
                check_complete_login(a.outcome, out, buf, groups).map_err(complete_login_fault)
            }
            slot::FIELDS => {
                let input = a.input::<FieldsIn>()?;
                let out = a.out::<FieldsOut>()?;
                let fields: &[FieldSpan] = if a.outcome == Outcome::Ready {
                    // SAFETY: `input.fields` is the host's own array of `fields_cap` live
                    // `FieldSpan`s from the op's `in`; `reported` refuses a count above that cap
                    // before it builds the slice.
                    unsafe {
                        reported(
                            input.fields.cast_const(),
                            u64::from(out.fields_len),
                            u64::from(input.fields_cap),
                            "fields.fields",
                        )?
                    }
                } else {
                    &[]
                };
                check_fields(
                    a.outcome,
                    out,
                    input.field_buf_cap,
                    input.fields_cap,
                    fields,
                )
                .map_err(fields_fault)
            }
            slot::BEGIN_LOGIN => {
                a.input::<BeginLoginIn>()?;
                check_begin_login(a.outcome, a.out::<BeginLoginOut>()?).map_err(begin_login_fault)
            }
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::VERIFY | slot::COMPLETE_LOGIN => a
                .out::<IdentifyOut>()
                .is_ok_and(|o| o.needed_bytes != 0 || o.needed_groups != 0),
            slot::FIELDS => a
                .out::<FieldsOut>()
                .is_ok_and(|o| o.needed_bytes != 0 || o.needed_fields != 0),
            _ => false,
        }
    }
}
