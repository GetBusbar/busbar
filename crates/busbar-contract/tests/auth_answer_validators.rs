// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ANSWER VALIDATORS, RULE BY RULE (ARCHITECT ruling: answer validators live with the
//! shape). Each test starts from an answer the validator accepts, breaks exactly one rule, and
//! asserts the named FAULT, so removing any one check turns its test red.

use busbar_contract::abi::auth::{
    check_begin_login, check_complete_login, check_fields, check_identify, BeginLoginOut,
    FieldSpan, FieldsOut, IdentifyOut, IdentityBuf, LoginField, Span, BEGIN_AUTHORIZE, BEGIN_FORM,
    FIELDS_HARD_MAX, IDENTITY_GROUPS_HARD_MAX, LOGIN_IDENTITY, LOGIN_OUTAGE, SPAN_ABSENT,
    VERDICT_IDENTITY, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};

const CAP: usize = 64;
const GROUPS_CAP: u32 = 4;
const FIELDS_CAP: u32 = 4;

fn zeroed<T>() -> T {
    // SAFETY: every type zeroed here is a `#[repr(C)]` struct of integers, raw pointers and
    // `Option` of fn pointers, for which all-zero bytes are a valid value.
    unsafe { std::mem::zeroed() }
}

fn sp(off: u32, len: u32) -> Span {
    Span { off, len }
}

const ABSENT: Span = Span {
    off: SPAN_ABSENT,
    len: 0,
};

fn buf() -> IdentityBuf {
    let mut b: IdentityBuf = zeroed();
    b.buf_cap = CAP;
    b.groups_cap = GROUPS_CAP;
    b
}

/// A READY identity the validator accepts: subject at 0..4, every optional span absent.
fn identity() -> IdentifyOut {
    let mut o: IdentifyOut = zeroed();
    o.verdict = VERDICT_IDENTITY;
    let id = &mut o.identity;
    id.subject = sp(0, 4);
    for s in [
        &mut id.key_id,
        &mut id.key_name,
        &mut id.user,
        &mut id.provider,
        &mut id.name,
        &mut id.claims,
    ] {
        *s = ABSENT;
    }
    o
}

fn red(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

fn ready_identity(o: &IdentifyOut, groups: &[Span]) -> Result<(), Fault> {
    check_identify(Outcome::Ready, o, &buf(), groups)
}

#[test]
fn the_baselines_are_accepted() {
    assert_eq!(ready_identity(&identity(), &[]), Ok(()));
    let mut o = identity();
    o.identity.groups_len = 1;
    assert_eq!(ready_identity(&o, &[sp(4, 4)]), Ok(()));
    let mut r: IdentifyOut = zeroed();
    r.verdict = VERDICT_REJECT;
    assert_eq!(ready_identity(&r, &[]), Ok(()));
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[field()]),
        Ok(())
    );
    assert_eq!(check_begin_login(Outcome::Ready, &authorize()), Ok(()));
}

#[test]
fn a_span_whose_end_overflows_u32_is_out_of_bounds() {
    let mut o = identity();
    o.identity.subject = sp(u32::MAX - 1, 2);
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::SpanOutOfBounds, "verify.span_out_of_bounds")
    );
}

#[test]
fn a_span_one_past_the_capacity_is_out_of_bounds() {
    let mut o = identity();
    o.identity.name = sp(CAP as u32 - 3, 4);
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::SpanOutOfBounds, "verify.span_out_of_bounds")
    );
    let mut f = field();
    f.value = sp(CAP as u32 - 3, 4);
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[f]),
        red(Rule::SpanOutOfBounds, "fields.span_out_of_bounds")
    );
}

#[test]
fn an_absent_span_with_a_length_is_fault() {
    let mut o = identity();
    o.identity.user = sp(SPAN_ABSENT, 3);
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::SpanNotAbsent, "verify.absent_with_len")
    );
}

#[test]
fn an_identity_without_a_subject_is_fault() {
    let mut o = identity();
    o.identity.subject = ABSENT;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::Missing, "verify.missing")
    );
}

#[test]
fn groups_one_past_the_capacity_is_fault() {
    let mut o = identity();
    o.identity.groups_len = GROUPS_CAP + 1;
    let g = vec![sp(0, 1); GROUPS_CAP as usize + 1];
    assert_eq!(
        ready_identity(&o, &g),
        red(Rule::OverCap, "verify.count_over_cap")
    );
}

#[test]
fn fields_one_past_the_capacity_is_fault() {
    let f = vec![field(); FIELDS_CAP as usize + 1];
    assert_eq!(
        check_fields(
            Outcome::Ready,
            &fields_out(FIELDS_CAP + 1),
            CAP,
            FIELDS_CAP,
            &f
        ),
        red(Rule::OverCap, "fields.count_over_cap")
    );
}

#[test]
fn ready_with_needed_is_fault() {
    let mut o = identity();
    o.needed_groups = 1;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::NeededNotFailed, "verify.groups")
    );
    let mut o = identity();
    o.needed_bytes = 1;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::NeededNotFailed, "verify.bytes")
    );
    let mut f = fields_out(1);
    f.needed_bytes = 1;
    assert_eq!(
        check_fields(Outcome::Ready, &f, CAP, FIELDS_CAP, &[field()]),
        red(Rule::NeededNotFailed, "fields.bytes")
    );
}

#[test]
fn needed_bytes_above_u32_max_or_counts_above_the_hard_max_are_fault() {
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = u64::from(u32::MAX) + 1;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[]),
        red(Rule::OverMax, "verify.bytes")
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_groups = IDENTITY_GROUPS_HARD_MAX + 1;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[]),
        red(Rule::OverMax, "verify.groups")
    );
    let mut f: FieldsOut = zeroed();
    f.needed_fields = FIELDS_HARD_MAX + 1;
    assert_eq!(
        check_fields(Outcome::Failed, &f, CAP, FIELDS_CAP, &[]),
        red(Rule::OverMax, "fields.fields")
    );
}

#[test]
fn failed_with_a_need_the_capacity_covers_is_fault() {
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[]),
        red(Rule::WastedRecall, "verify")
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_groups = GROUPS_CAP;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[]),
        red(Rule::WastedRecall, "verify")
    );
    let mut f: FieldsOut = zeroed();
    f.needed_fields = 1;
    assert_eq!(
        check_fields(Outcome::Failed, &f, CAP, FIELDS_CAP, &[]),
        red(Rule::WastedRecall, "fields")
    );
    // A real short answer, and a real failure, are both accepted.
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64 + 1;
    assert_eq!(check_identify(Outcome::Failed, &o, &buf(), &[]), Ok(()));
    assert_eq!(
        check_identify(Outcome::Failed, &zeroed(), &buf(), &[]),
        Ok(())
    );
}

#[test]
fn a_verdict_outside_the_vocabulary_is_fault() {
    let mut o = identity();
    o.verdict = 0;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::UnknownCode, "verify.vocabulary")
    );
    o.verdict = 4;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::UnknownCode, "verify.vocabulary")
    );
}

#[test]
fn an_unknown_flag_bit_is_fault() {
    let mut o = identity();
    o.identity.flags = 2;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::UnknownCode, "verify.unknown_flags")
    );
    let mut f = field();
    f.flags = 2;
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[f]),
        red(Rule::UnknownCode, "fields.unknown_flags")
    );
}

#[test]
fn a_form_count_with_a_null_form_is_fault() {
    let mut o = authorize();
    o.shape = BEGIN_FORM;
    o.authorize_url = zeroed();
    o.form_len = 1;
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::NullWithCount, "begin_login.null_with_count")
    );
}

#[test]
fn a_shape_with_no_bit_or_two_bits_is_fault() {
    let mut o = authorize();
    o.shape = 0;
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::NotExactlyOne, "begin_login.not_exactly_one")
    );
    o.shape = BEGIN_AUTHORIZE | BEGIN_FORM;
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::NotExactlyOne, "begin_login.not_exactly_one")
    );
    o.shape = 4;
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::UnknownCode, "begin_login.vocabulary")
    );
}

#[test]
fn the_part_a_shape_names_must_be_present() {
    let mut o = authorize();
    o.authorize_url = zeroed();
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::Missing, "begin_login.missing")
    );
    let form = [LoginField {
        name: zeroed(),
        label: zeroed(),
        kind: 1,
        required: 1,
    }];
    let mut o = authorize();
    o.shape = BEGIN_FORM;
    o.form = form.as_ptr();
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::Missing, "begin_login.missing")
    );
    o.form_len = 1;
    assert_eq!(check_begin_login(Outcome::Ready, &o), Ok(()));
}

#[test]
fn a_url_length_with_a_null_pointer_is_fault() {
    let mut o = authorize();
    o.authorize_url.ptr = std::ptr::null();
    assert_eq!(
        check_begin_login(Outcome::Ready, &o),
        red(Rule::NullWithCount, "begin_login.null_with_count")
    );
}

fn field() -> FieldSpan {
    FieldSpan {
        name: sp(0, 13),
        value: sp(13, 20),
        flags: 1,
        _reserved: 0,
    }
}

fn fields_out(n: u32) -> FieldsOut {
    let mut f: FieldsOut = zeroed();
    f.fields_len = n;
    f
}

const URL: &str = "https://idp.example/authorize";

fn authorize() -> BeginLoginOut {
    let mut o: BeginLoginOut = zeroed();
    o.shape = BEGIN_AUTHORIZE;
    o.authorize_url.ptr = URL.as_ptr();
    o.authorize_url.len = URL.len();
    o
}

#[test]
fn a_claims_format_outside_the_blob_vocabulary_is_fault() {
    let mut o = identity();
    o.identity.claims_fmt = 4;
    assert_eq!(
        ready_identity(&o, &[]),
        red(Rule::UnknownCode, "verify.vocabulary")
    );
}

#[test]
fn an_absent_group_span_is_fault() {
    let mut o = identity();
    o.identity.groups_len = 1;
    assert_eq!(
        ready_identity(&o, &[ABSENT]),
        red(Rule::Missing, "verify.missing")
    );
    let mut f = field();
    f.name = ABSENT;
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[f]),
        red(Rule::Missing, "fields.missing")
    );
}

#[test]
fn a_count_that_disagrees_with_the_slice_is_fault() {
    let mut o = identity();
    o.identity.groups_len = 2;
    assert_eq!(
        ready_identity(&o, &[sp(0, 1)]),
        red(Rule::Contradiction, "verify.count_mismatch")
    );
}

#[test]
fn a_fields_count_that_disagrees_with_the_slice_is_fault() {
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(2), CAP, FIELDS_CAP, &[field()]),
        red(Rule::Contradiction, "fields.count_mismatch")
    );
}

#[test]
fn ready_fields_with_needed_fields_is_fault() {
    let mut f = fields_out(1);
    f.needed_fields = 1;
    assert_eq!(
        check_fields(Outcome::Ready, &f, CAP, FIELDS_CAP, &[field()]),
        red(Rule::NeededNotFailed, "fields.fields")
    );
}

#[test]
fn refused_or_pending_identify_with_needed_is_fault() {
    for outcome in [Outcome::Refused, Outcome::Pending] {
        let mut o: IdentifyOut = zeroed();
        assert_eq!(check_identify(outcome, &o, &buf(), &[]), Ok(()));
        o.needed_bytes = CAP as u64 + 1;
        assert_eq!(
            check_identify(outcome, &o, &buf(), &[]),
            red(Rule::NeededNotFailed, "verify.bytes")
        );
    }
}

#[test]
fn refused_or_pending_fields_with_needed_is_fault() {
    for outcome in [Outcome::Refused, Outcome::Pending] {
        let mut f: FieldsOut = zeroed();
        assert_eq!(check_fields(outcome, &f, CAP, FIELDS_CAP, &[]), Ok(()));
        f.needed_fields = FIELDS_CAP + 1;
        assert_eq!(
            check_fields(outcome, &f, CAP, FIELDS_CAP, &[]),
            red(Rule::NeededNotFailed, "fields.fields")
        );
    }
}

#[test]
fn complete_login_checks_its_own_vocabulary() {
    let mut o = identity();
    o.verdict = LOGIN_IDENTITY;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        Ok(())
    );
    o.verdict = LOGIN_OUTAGE;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        Ok(())
    );
    o.verdict = LOGIN_OUTAGE + 1;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        red(Rule::UnknownCode, "complete_login.vocabulary")
    );
    o.verdict = 0;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        red(Rule::UnknownCode, "complete_login.vocabulary")
    );
}

/// M-SB REFINEMENT: one dimension short with the other reporting a fitting full size is a legal
/// short FAILED; both fitting is FAULT.
#[test]
fn a_short_identify_reports_every_dimension_full_size() {
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64 + 1;
    o.needed_groups = GROUPS_CAP;
    assert_eq!(check_identify(Outcome::Failed, &o, &buf(), &[]), Ok(()));
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64;
    o.needed_groups = GROUPS_CAP + 1;
    assert_eq!(check_identify(Outcome::Failed, &o, &buf(), &[]), Ok(()));
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64;
    o.needed_groups = GROUPS_CAP;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[]),
        red(Rule::WastedRecall, "verify")
    );
}

#[test]
fn a_short_fields_reports_every_dimension_full_size() {
    let mut f: FieldsOut = zeroed();
    f.needed_bytes = CAP as u64 + 1;
    f.needed_fields = 2;
    assert_eq!(
        check_fields(Outcome::Failed, &f, CAP, FIELDS_CAP, &[]),
        Ok(())
    );
    let mut f: FieldsOut = zeroed();
    f.needed_bytes = 10;
    f.needed_fields = FIELDS_CAP + 1;
    assert_eq!(
        check_fields(Outcome::Failed, &f, CAP, FIELDS_CAP, &[]),
        Ok(())
    );
    let mut f: FieldsOut = zeroed();
    f.needed_bytes = 10;
    f.needed_fields = 2;
    assert_eq!(
        check_fields(Outcome::Failed, &f, CAP, FIELDS_CAP, &[]),
        red(Rule::WastedRecall, "fields")
    );
}
