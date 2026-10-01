// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ANSWER VALIDATORS, RULE BY RULE (ARCHITECT ruling: answer validators live with the
//! shape). Each test starts from an answer the validator accepts, breaks exactly one rule, and
//! asserts the named FAULT, so removing any one check turns its test red.

use busbar_contract::abi::auth::{
    check_begin_login, check_complete_login, check_fields, check_identify, check_style_decl,
    BeginLoginOut, FieldSpan, FieldsOut, IdentifyOut, IdentityBuf, LoginField, BEGIN_AUTHORIZE,
    BEGIN_FORM, FIELDS_HARD_MAX, FIELD_QUERY, FIELD_SENSITIVE, IDENTITY_GROUPS_HARD_MAX,
    LOGIN_IDENTITY, LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED, SPAN_ABSENT, STYLE_CALLER_CREDENTIAL,
    STYLE_NEEDS_HEADERS, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::auth::{
    check_inbound_points, check_points, AuthPoint, AuthPoints, StripName, CAP_INBOUND, CAP_LOGIN,
    CAP_OUTBOUND, DECISION_CONTINUE, DECISION_STOP, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY,
    POINT_PEER, STRIP_FIELD, STRIP_QUERY,
};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};

const CAP: usize = 64;
const GROUPS_CAP: u32 = 4;
const FIELDS_CAP: u32 = 4;
const STRIP_CAP: u32 = 4;

fn zeroed<T>() -> T {
    // SAFETY: every type zeroed here is a `#[repr(C)]` struct of integers, raw pointers and
    // `Option` of fn pointers, for which all-zero bytes are a valid value.
    unsafe { std::mem::zeroed() }
}

fn sp(off: u32, len: u32) -> Span {
    Span { offset: off, len }
}

const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
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

fn red<T>(rule: Rule, field: &'static str) -> Result<T, Fault> {
    Err(fault(rule, field))
}

/// `o` as a READY `verify` answer: with the decision every READY verify carries.
fn ready_identity(o: &IdentifyOut, groups: &[Span]) -> Result<(), Fault> {
    let mut v = *o;
    v.decision = DECISION_CONTINUE;
    check_identify(Outcome::Ready, &v, &buf(), groups, STRIP_CAP, &[])
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
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        red(Rule::OverMax, "verify.bytes")
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_groups = IDENTITY_GROUPS_HARD_MAX + 1;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
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
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        red(Rule::WastedRecall, "verify")
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_groups = GROUPS_CAP;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
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
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        Ok(())
    );
    assert_eq!(
        check_identify(Outcome::Failed, &zeroed(), &buf(), &[], STRIP_CAP, &[]),
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
    f.flags = 4;
    assert_eq!(
        check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[f]),
        red(Rule::UnknownCode, "fields.unknown_flags")
    );
}

#[test]
fn a_query_field_is_a_known_flag() {
    for flags in [FIELD_QUERY, FIELD_QUERY | FIELD_SENSITIVE] {
        let mut f = field();
        f.flags = flags;
        assert_eq!(
            check_fields(Outcome::Ready, &fields_out(1), CAP, FIELDS_CAP, &[f]),
            Ok(())
        );
    }
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
        assert_eq!(
            check_identify(outcome, &o, &buf(), &[], STRIP_CAP, &[]),
            Ok(())
        );
        o.needed_bytes = CAP as u64 + 1;
        assert_eq!(
            check_identify(outcome, &o, &buf(), &[], STRIP_CAP, &[]),
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
    o.verdict = LOGIN_SECURITY_CHECK_FAILED;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        Ok(())
    );
    o.verdict = LOGIN_SECURITY_CHECK_FAILED + 1;
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
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        Ok(())
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64;
    o.needed_groups = GROUPS_CAP + 1;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        Ok(())
    );
    let mut o: IdentifyOut = zeroed();
    o.needed_bytes = CAP as u64;
    o.needed_groups = GROUPS_CAP;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
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

#[test]
fn a_style_decl_flag_vocabulary_is_the_two_known_bits() {
    let head = POINT_HEAD;
    assert_eq!(check_style_decl(0, head), Ok(AuthPoints::HEAD));
    assert_eq!(
        check_style_decl(STYLE_NEEDS_HEADERS, head),
        Ok(AuthPoints::HEAD)
    );
    assert_eq!(
        check_style_decl(STYLE_CALLER_CREDENTIAL, head),
        Ok(AuthPoints::HEAD)
    );
    assert_eq!(
        check_style_decl(
            STYLE_NEEDS_HEADERS | STYLE_CALLER_CREDENTIAL,
            POINT_HEAD_BODY
        ),
        Ok(AuthPoints::HEAD_BODY)
    );
}

#[test]
fn a_style_decl_flag_outside_the_vocabulary_is_fault() {
    assert_eq!(check_style_decl(1 << 31, POINT_HEAD), red(Rule::UnknownCode, "style.unknown_flags"));
    assert_eq!(
        check_style_decl(STYLE_CALLER_CREDENTIAL | (1 << 3), POINT_HEAD),
        red(Rule::UnknownCode, "style.unknown_flags")
    );
    // RED: the retired body-hash flag bit (1) is no longer in the vocabulary: a style that signs
    // the body needs `HeadBody` instead.
    assert_eq!(check_style_decl(1, POINT_HEAD), red(Rule::UnknownCode, "style.unknown_flags"));
}

/// RED: a style needs at least one point, and a valid set (THE DESIGN, "Auth points and guest
/// lists", step 1).
#[test]
fn a_style_decl_needs_a_valid_non_empty_point_set() {
    assert_eq!(check_style_decl(0, 0), red(Rule::Missing, "points.missing"));
    assert_eq!(check_style_decl(0, POINT_FRAME), red(Rule::UnknownCode, "points.reserved_point"));
    assert_eq!(
        check_style_decl(0, POINT_HEAD | POINT_HEAD_BODY),
        red(Rule::Contradiction, "points.points_overlap")
    );
    assert_eq!(check_style_decl(0, 1 << 9), red(Rule::UnknownCode, "style.unknown_flags"));
}

/// THE POINT SET RULES, one RED each: an unknown bit, the reserved `Frame`, `Head` with `HeadBody`,
/// and empty where a set is required. Every other set is accepted.
#[test]
fn check_points_refuses_each_broken_set() {
    assert_eq!(check_points(1 << 4, false), red(Rule::UnknownCode, "points.unknown_flags"));
    assert_eq!(check_points(u32::MAX, false), red(Rule::UnknownCode, "points.unknown_flags"));
    assert_eq!(check_points(POINT_FRAME, false), red(Rule::UnknownCode, "points.reserved_point"));
    assert_eq!(
        check_points(POINT_HEAD | POINT_FRAME, false),
        red(Rule::UnknownCode, "points.reserved_point")
    );
    assert_eq!(
        check_points(POINT_HEAD | POINT_HEAD_BODY, false),
        red(Rule::Contradiction, "points.points_overlap")
    );
    assert_eq!(
        check_points(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY, false),
        red(Rule::Contradiction, "points.points_overlap")
    );
    assert_eq!(check_points(0, true), red(Rule::Missing, "points.missing"));
    assert_eq!(check_points(0, false), Ok(AuthPoints::EMPTY));
    for ok in [
        POINT_PEER,
        POINT_HEAD,
        POINT_HEAD_BODY,
        POINT_PEER | POINT_HEAD,
        POINT_PEER | POINT_HEAD_BODY,
    ] {
        assert_eq!(check_points(ok, true), Ok(AuthPoints(ok)));
    }
    // `check_points` is `const`: a plugin's tail is judged at compile time too.
    const HEAD: Result<AuthPoints, Fault> = check_points(POINT_HEAD, true);
    assert_eq!(HEAD, Ok(AuthPoints::HEAD));
}

/// THE POINT ORDER: `Peer` < `Head` < `HeadBody`, and each point is its own bit.
#[test]
fn the_points_are_ordered_and_are_their_bits() {
    assert!(AuthPoint::Peer < AuthPoint::Head);
    assert!(AuthPoint::Head < AuthPoint::HeadBody);
    for (p, bit) in [
        (AuthPoint::Peer, POINT_PEER),
        (AuthPoint::Head, POINT_HEAD),
        (AuthPoint::HeadBody, POINT_HEAD_BODY),
        (AuthPoint::Frame, POINT_FRAME),
    ] {
        assert_eq!(p.bit(), bit);
        assert_eq!(AuthPoint::from_bit(bit), Some(p));
    }
    assert_eq!(AuthPoint::from_bit(0), None);
    assert_eq!(AuthPoint::from_bit(POINT_PEER | POINT_HEAD), None);
    assert!(AuthPoints(POINT_PEER | POINT_HEAD).has(AuthPoint::Head));
    assert!(!AuthPoints::HEAD.has(AuthPoint::HeadBody));
    assert!(AuthPoints::EMPTY.is_empty());
}

/// THE TAIL'S INBOUND POINTS: with `CAP_INBOUND` a valid, non-empty set; without it `0`.
#[test]
fn the_inbound_points_follow_the_inbound_capability() {
    assert_eq!(
        check_inbound_points(CAP_INBOUND, POINT_HEAD_BODY),
        Ok(AuthPoints::HEAD_BODY)
    );
    assert_eq!(check_inbound_points(CAP_OUTBOUND, 0), Ok(AuthPoints::EMPTY));
    assert_eq!(check_inbound_points(CAP_LOGIN, 0), Ok(AuthPoints::EMPTY));
    // RED: an inbound plugin with no point, or a bad set.
    assert_eq!(check_inbound_points(CAP_INBOUND, 0), red(Rule::Missing, "points.missing"));
    assert_eq!(
        check_inbound_points(CAP_INBOUND | CAP_LOGIN, POINT_FRAME),
        red(Rule::UnknownCode, "points.reserved_point")
    );
    // RED: points stated by a plugin that serves no `verify`.
    assert_eq!(
        check_inbound_points(CAP_OUTBOUND, POINT_HEAD),
        red(Rule::Contradiction, "points.unexpected")
    );
}

fn strip(off: u32, len: u32, place: u32) -> StripName {
    StripName {
        name: sp(off, len),
        place,
        _reserved: 0,
    }
}

/// A READY verify answer with a decision and two strips, one per place, as the validator accepts.
fn stripped(verdict: u32) -> IdentifyOut {
    let mut o = if verdict == VERDICT_IDENTITY {
        identity()
    } else {
        let mut o: IdentifyOut = zeroed();
        o.verdict = verdict;
        o
    };
    o.decision = DECISION_STOP;
    o.strip_len = 2;
    o
}

const STRIPS: [StripName; 2] = [
    StripName {
        name: Span { offset: 8, len: 13 },
        place: STRIP_FIELD,
        _reserved: 0,
    },
    StripName {
        name: Span { offset: 21, len: 3 },
        place: STRIP_QUERY,
        _reserved: 0,
    },
];

fn ready_verify(o: &IdentifyOut, strips: &[StripName]) -> Result<(), Fault> {
    check_identify(Outcome::Ready, o, &buf(), &[], STRIP_CAP, strips)
}

/// Strips are named whatever the verdict (THE DESIGN, "Auth points and guest lists", step 3).
#[test]
fn strips_are_accepted_with_every_verdict() {
    for v in [VERDICT_IDENTITY, VERDICT_REJECT, VERDICT_PASS] {
        assert_eq!(ready_verify(&stripped(v), &STRIPS), Ok(()), "verdict {v}");
    }
}

/// RED: the decision vocabulary is CONTINUE | STOP; `0` and any other value are FAULT.
#[test]
fn a_decision_outside_the_vocabulary_is_fault() {
    let mut o = stripped(VERDICT_PASS);
    o.decision = DECISION_CONTINUE;
    assert_eq!(ready_verify(&o, &STRIPS), Ok(()));
    for bad in [0, 3, u32::MAX] {
        o.decision = bad;
        assert_eq!(ready_verify(&o, &STRIPS), red(Rule::UnknownCode, "verify.vocabulary"), "{bad}");
    }
}

/// RED: each strip rule — the count over the capacity, a count that disagrees with the slice, an
/// unknown place, a span past the buffer, an absent name.
#[test]
fn each_broken_strip_is_fault() {
    let mut o = stripped(VERDICT_REJECT);
    o.strip_len = STRIP_CAP + 1;
    assert_eq!(ready_verify(&o, &STRIPS), red(Rule::OverCap, "verify.count_over_cap"));
    o.strip_len = 1;
    assert_eq!(ready_verify(&o, &STRIPS), red(Rule::Contradiction, "verify.count_mismatch"));
    let o = stripped(VERDICT_REJECT);
    assert_eq!(
        ready_verify(&o, &[STRIPS[0], strip(21, 3, 0)]),
        red(Rule::UnknownCode, "verify.vocabulary")
    );
    assert_eq!(
        ready_verify(&o, &[STRIPS[0], strip(21, 3, STRIP_FIELD | STRIP_QUERY)]),
        red(Rule::UnknownCode, "verify.vocabulary")
    );
    assert_eq!(
        ready_verify(&o, &[STRIPS[0], strip(60, 5, STRIP_QUERY)]),
        red(Rule::SpanOutOfBounds, "verify.span_out_of_bounds")
    );
    assert_eq!(
        ready_verify(&o, &[STRIPS[0], strip(SPAN_ABSENT, 0, STRIP_QUERY)]),
        red(Rule::Missing, "verify.missing")
    );
}

/// RED: a credential rides only an identity, in bounds; `len == 0` is absent.
#[test]
fn a_credential_rides_only_an_identity() {
    let mut o = stripped(VERDICT_IDENTITY);
    o.identity.credential = sp(24, 6);
    assert_eq!(ready_verify(&o, &STRIPS), Ok(()));
    o.identity.credential = sp(60, 6);
    assert_eq!(ready_verify(&o, &STRIPS), red(Rule::SpanOutOfBounds, "verify.span_out_of_bounds"));
    for v in [VERDICT_REJECT, VERDICT_PASS] {
        let mut o = stripped(v);
        o.identity.credential = sp(24, 6);
        assert_eq!(ready_verify(&o, &STRIPS), red(Rule::Contradiction, "verify.unexpected"), "{v}");
        o.identity.credential = sp(24, 0);
        assert_eq!(ready_verify(&o, &STRIPS), Ok(()), "len 0 is absent");
    }
}

/// THE STRIP ARRAY'S SHORT ANSWER, and its REDs: a strip need past the hard maximum, a strip need
/// on READY, REFUSED or PENDING.
#[test]
fn the_strip_array_has_the_short_buffer_rules() {
    let mut o: IdentifyOut = zeroed();
    o.needed_strip = STRIP_CAP + 1;
    o.needed_bytes = 13;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        Ok(())
    );
    o.needed_strip = FIELDS_HARD_MAX + 1;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        red(Rule::OverMax, "verify.strip")
    );
    o.needed_strip = STRIP_CAP;
    assert_eq!(
        check_identify(Outcome::Failed, &o, &buf(), &[], STRIP_CAP, &[]),
        red(Rule::WastedRecall, "verify")
    );
    let mut r = stripped(VERDICT_PASS);
    r.needed_strip = 1;
    assert_eq!(ready_verify(&r, &STRIPS), red(Rule::NeededNotFailed, "verify.strip"));
    for outcome in [Outcome::Refused, Outcome::Pending] {
        let mut p: IdentifyOut = zeroed();
        p.needed_strip = 1;
        assert_eq!(
            check_identify(outcome, &p, &buf(), &[], STRIP_CAP, &[]),
            red(Rule::NeededNotFailed, "verify.strip")
        );
    }
}

/// RED: a login answers no decision, names no strip and carries no credential.
#[test]
fn a_login_carries_no_decision_strip_or_credential() {
    let mut o = identity();
    o.verdict = LOGIN_IDENTITY;
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        Ok(())
    );
    for broken in [
        IdentifyOut {
            decision: DECISION_CONTINUE,
            ..o
        },
        IdentifyOut { strip_len: 1, ..o },
        IdentifyOut {
            needed_strip: 1,
            ..o
        },
    ] {
        assert_eq!(
            check_complete_login(Outcome::Ready, &broken, &buf(), &[]),
            red(Rule::Contradiction, "complete_login.unexpected")
        );
    }
    o.identity.credential = sp(24, 6);
    assert_eq!(
        check_complete_login(Outcome::Ready, &o, &buf(), &[]),
        red(Rule::Contradiction, "complete_login.unexpected")
    );
}
