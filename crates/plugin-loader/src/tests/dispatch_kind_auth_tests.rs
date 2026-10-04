// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth kind's `Kind` adapter over crafted answers: for each checked op a legal answer, a
//! broken rule, a reported count one above the host's cap over a dangling array (FAULT before any
//! slice exists), and an `in` smaller than the op's struct; then the short-buffer reading.

use std::mem::size_of;
use std::ptr::NonNull;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, IdentityOut, OpenOutboundIn, OpenOutboundOut, RequestFacts,
    StripName, VerifyIn, BEGIN_AUTHORIZE, BEGIN_FORM, DECISION_CONTINUE, FIELD_SENSITIVE,
    LOGIN_IDENTITY, MODE_OWN, POINT_HEAD, SPAN_ABSENT, STRIP_FIELD, VERDICT_IDENTITY, VERDICT_PASS,
};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, Span};
use busbar_contract::abi::mechanism::check::{Fault, Rule};
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{in_head, out_head, Answer, Kind, NO_BLOB};

const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};
const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};
const BUF_CAP: usize = 64;
const GROUPS_CAP: u32 = 2;
const FIELDS_CAP: u32 = 2;

/// The answer of op `slot` over `input`/`out`, `in_size` bytes of `in`.
fn answer<I, O>(
    slot: u32,
    outcome: Outcome,
    input: &I,
    in_size: usize,
    out: &O,
) -> Answer<'static> {
    // SAFETY: `input`/`out` are live test locals that outlive the answer and are not written while
    // it lives; `in_size` is at most `size_of::<I>()` and the out size is exactly `size_of::<O>()`.
    unsafe {
        Answer::new(
            slot,
            outcome,
            std::ptr::from_ref(input).cast::<InHead>(),
            in_size,
            std::ptr::from_ref(out).cast::<OutHead>(),
            size_of::<O>(),
        )
    }
}

fn check<I, O>(slot: u32, outcome: Outcome, input: &I, out: &O) -> Result<(), Fault> {
    Auth::check(&answer(slot, outcome, input, size_of::<I>(), out))
}

fn rule(r: Result<(), Fault>) -> Rule {
    r.expect_err("the answer is FAULT").rule
}

fn facts() -> RequestFacts {
    RequestFacts {
        method: NO_STR,
        authority: NO_STR,
        canonical_path: NO_STR,
        query: NO_STR,
        timestamp: 0,
    }
}

fn identity_buf(bytes: &mut [u8; BUF_CAP], groups: *mut Span, groups_cap: u32) -> IdentityBuf {
    IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: BUF_CAP,
        groups,
        groups_cap,
        _reserved: 0,
    }
}

fn verify_in(out_buf: IdentityBuf) -> VerifyIn {
    verify_in_with(out_buf, std::ptr::null_mut(), 0)
}

fn verify_in_with(out_buf: IdentityBuf, strip: *mut StripName, strip_cap: u32) -> VerifyIn {
    VerifyIn {
        head: in_head(),
        credential: NO_BLOB,
        lines: std::ptr::null(),
        lines_len: 0,
        request: facts(),
        out_buf,
        point: POINT_HEAD,
        _reserved: 0,
        conn: 0,
        unit: 0,
        peer: NO_BLOB,
        body: NO_BLOB,
        strip,
        strip_cap,
        _reserved2: 0,
    }
}

/// A READY `verify` answer: `identified` with the decision every READY verify carries.
fn verified(verdict: u32, groups_len: u32) -> IdentifyOut {
    IdentifyOut {
        decision: DECISION_CONTINUE,
        ..identified(verdict, groups_len)
    }
}

fn complete_login_in(out_buf: IdentityBuf) -> CompleteLoginIn {
    CompleteLoginIn {
        head: in_head(),
        code: NO_BLOB,
        state: NO_STR,
        redirect_uri: NO_STR,
        code_verifier: NO_BLOB,
        submitted: std::ptr::null(),
        submitted_len: 0,
        out_buf,
        nonce: NO_STR,
    }
}

/// An identity `verdict` with subject `0..5` and `groups_len` groups.
fn identified(verdict: u32, groups_len: u32) -> IdentifyOut {
    IdentifyOut {
        head: out_head(),
        verdict,
        needed_groups: 0,
        needed_bytes: 0,
        identity: IdentityOut {
            subject: Span { offset: 0, len: 5 },
            key_id: ABSENT,
            key_name: ABSENT,
            user: ABSENT,
            provider: ABSENT,
            name: ABSENT,
            claims: ABSENT,
            claims_fmt: 0,
            flags: 0,
            ttl_secs: 0,
            groups_len,
            _reserved: 0,
            replay_key: ABSENT,
            replay_ttl_secs: 0,
            credential: ABSENT,
        },
        decision: 0,
        strip_len: 0,
        needed_strip: 0,
        _reserved: 0,
    }
}

fn fields_in(bytes: &mut [u8; BUF_CAP], fields: *mut FieldSpan, fields_cap: u32) -> FieldsIn {
    FieldsIn {
        head: in_head(),
        handle: 1,
        mode: MODE_OWN,
        point: POINT_HEAD,
        request: facts(),
        caller_credential: NO_BLOB,
        field_buf: bytes.as_mut_ptr(),
        field_buf_cap: BUF_CAP,
        fields,
        fields_cap,
        _reserved: 0,
        headers: std::ptr::null(),
        headers_len: 0,
        conn: 0,
        unit: 0,
        body: NO_BLOB,
    }
}

fn fields_out(fields_len: u32) -> FieldsOut {
    FieldsOut {
        head: out_head(),
        fields_len,
        needed_fields: 0,
        needed_bytes: 0,
    }
}

fn field(flags: u32) -> FieldSpan {
    FieldSpan {
        name: Span { offset: 0, len: 13 },
        value: Span {
            offset: 13,
            len: 20,
        },
        flags,
        _reserved: 0,
    }
}

fn begin_login_in() -> BeginLoginIn {
    BeginLoginIn {
        head: in_head(),
        redirect_uri: NO_STR,
        state: NO_STR,
        nonce: NO_STR,
        code_challenge: NO_STR,
        scopes: std::ptr::null(),
        scopes_len: 0,
    }
}

fn begin_login_out(shape: u32, url: &'static str) -> BeginLoginOut {
    BeginLoginOut {
        head: out_head(),
        shape,
        _reserved: 0,
        authorize_url: AbiStr {
            ptr: url.as_ptr(),
            len: url.len(),
        },
        form: std::ptr::null(),
        form_len: 0,
    }
}

#[test]
fn the_kind_names_its_code_timeout_and_ops() {
    assert_eq!(Auth::CODE, KindCode::Auth);
    assert_eq!(Auth::TIMEOUT, Outcome::Failed);
    for (s, name) in [
        (slot::VERIFY, "verify"),
        (slot::BEGIN_LOGIN, "begin_login"),
        (slot::COMPLETE_LOGIN, "complete_login"),
        (slot::OPEN_OUTBOUND, "open_outbound"),
        (slot::OUTBOUND_READY, "outbound_ready"),
        (slot::FIELDS, "fields"),
    ] {
        assert_eq!(Auth::op_name(s), name);
    }
    assert_eq!(Auth::op_name(0), "validate");
}

// ---- verify ----

#[test]
fn verify_green_identity_with_groups() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [Span { offset: 5, len: 4 }, ABSENT];
    let input = verify_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    assert_eq!(
        check(
            slot::VERIFY,
            Outcome::Ready,
            &input,
            &verified(VERDICT_IDENTITY, 1)
        ),
        Ok(())
    );
    assert_eq!(
        check(
            slot::VERIFY,
            Outcome::Ready,
            &input,
            &verified(VERDICT_PASS, 0)
        ),
        Ok(())
    );
}

#[test]
fn verify_red_a_span_past_the_buffer() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = verify_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let mut out = verified(VERDICT_IDENTITY, 0);
    out.identity.subject = Span {
        offset: 60,
        len: 10,
    };
    let f = check(slot::VERIFY, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!(f.rule, Rule::SpanOutOfBounds);
    assert_eq!(f.field, "verify.span_out_of_bounds");
}

#[test]
fn verify_red_groups_over_cap_builds_no_slice() {
    let mut bytes = [0u8; BUF_CAP];
    let input = verify_in(identity_buf(
        &mut bytes,
        NonNull::<Span>::dangling().as_ptr(),
        GROUPS_CAP,
    ));
    let out = verified(VERDICT_IDENTITY, GROUPS_CAP + 1);
    let f = check(slot::VERIFY, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!(f.rule, Rule::OverCap);
    assert_eq!(f.field, "verify.groups");
}

#[test]
fn verify_a_failure_never_reads_its_groups_count() {
    let mut bytes = [0u8; BUF_CAP];
    let input = verify_in(identity_buf(
        &mut bytes,
        NonNull::<Span>::dangling().as_ptr(),
        GROUPS_CAP,
    ));
    let out = identified(0, GROUPS_CAP + 1);
    assert_eq!(check(slot::VERIFY, Outcome::Failed, &input, &out), Ok(()));
}

#[test]
fn verify_red_a_foreign_in() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = verify_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let out = identified(VERDICT_IDENTITY, 0);
    let a = answer(
        slot::VERIFY,
        Outcome::Ready,
        &input,
        size_of::<VerifyIn>() - 1,
        &out,
    );
    assert_eq!(rule(Auth::check(&a)), Rule::Foreign);
}

/// THE STRIPS (THE DESIGN, "Auth points and guest lists", step 3): a READY verify's strip
/// names are read from the host's array whatever the verdict, bounded by its capacity.
#[test]
fn verify_green_strips_with_any_verdict() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let mut strips = [StripName {
        name: Span { offset: 20, len: 5 },
        place: STRIP_FIELD,
        _reserved: 0,
    }];
    let input = verify_in_with(
        identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP),
        strips.as_mut_ptr(),
        1,
    );
    for v in [VERDICT_IDENTITY, VERDICT_PASS] {
        let out = IdentifyOut {
            strip_len: 1,
            ..verified(v, 0)
        };
        assert_eq!(check(slot::VERIFY, Outcome::Ready, &input, &out), Ok(()));
    }
}

/// RED: a strip count over the host's capacity is FAULT before any slice is built; an unknown
/// place and a missing decision are the kind's vocabulary faults.
#[test]
fn verify_red_strips_and_decision() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = verify_in_with(
        identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP),
        NonNull::<StripName>::dangling().as_ptr(),
        1,
    );
    let out = IdentifyOut {
        strip_len: 2,
        ..verified(VERDICT_PASS, 0)
    };
    let f = check(slot::VERIFY, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::OverCap, "verify.strip"));

    let mut strips = [StripName {
        name: Span { offset: 20, len: 5 },
        place: 9,
        _reserved: 0,
    }];
    let input = verify_in_with(
        identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP),
        strips.as_mut_ptr(),
        1,
    );
    let out = IdentifyOut {
        strip_len: 1,
        ..verified(VERDICT_PASS, 0)
    };
    let f = check(slot::VERIFY, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::UnknownCode, "verify.vocabulary"));
    let f = check(
        slot::VERIFY,
        Outcome::Ready,
        &input,
        &identified(VERDICT_PASS, 0),
    )
    .unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::UnknownCode, "verify.vocabulary"));
    // A credential without an identity contradicts the verdict.
    let mut out = verified(VERDICT_PASS, 0);
    out.identity.credential = Span { offset: 0, len: 4 };
    let f = check(slot::VERIFY, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!(
        (f.rule, f.field),
        (Rule::Contradiction, "verify.unexpected")
    );
}

// ---- complete_login ----

#[test]
fn complete_login_green_identity_with_groups() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [Span { offset: 5, len: 4 }, Span { offset: 9, len: 0 }];
    let input = complete_login_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let out = identified(LOGIN_IDENTITY, 2);
    assert_eq!(
        check(slot::COMPLETE_LOGIN, Outcome::Ready, &input, &out),
        Ok(())
    );
}

#[test]
fn complete_login_red_a_verdict_outside_the_vocabulary() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = complete_login_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let f = check(
        slot::COMPLETE_LOGIN,
        Outcome::Ready,
        &input,
        &identified(0, 0),
    )
    .unwrap_err();
    assert_eq!(f.rule, Rule::UnknownCode);
    assert_eq!(f.field, "complete_login.vocabulary");
}

#[test]
fn complete_login_red_groups_over_cap_builds_no_slice() {
    let mut bytes = [0u8; BUF_CAP];
    let input = complete_login_in(identity_buf(
        &mut bytes,
        NonNull::<Span>::dangling().as_ptr(),
        GROUPS_CAP,
    ));
    let out = identified(LOGIN_IDENTITY, GROUPS_CAP + 1);
    let f = check(slot::COMPLETE_LOGIN, Outcome::Ready, &input, &out).unwrap_err();
    assert_eq!(f.rule, Rule::OverCap);
    assert_eq!(f.field, "complete_login.groups");
}

#[test]
fn complete_login_red_a_foreign_in() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = complete_login_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let out = identified(LOGIN_IDENTITY, 0);
    let a = answer(
        slot::COMPLETE_LOGIN,
        Outcome::Ready,
        &input,
        size_of::<CompleteLoginIn>() - 1,
        &out,
    );
    assert_eq!(rule(Auth::check(&a)), Rule::Foreign);
}

// ---- fields ----

#[test]
fn fields_green_one_field_and_none() {
    let mut bytes = [0u8; BUF_CAP];
    let mut fields = [field(FIELD_SENSITIVE), field(0)];
    let input = fields_in(&mut bytes, fields.as_mut_ptr(), FIELDS_CAP);
    assert_eq!(
        check(slot::FIELDS, Outcome::Ready, &input, &fields_out(2)),
        Ok(())
    );
    assert_eq!(
        check(slot::FIELDS, Outcome::Ready, &input, &fields_out(0)),
        Ok(())
    );
}

#[test]
fn fields_red_an_unknown_flag() {
    let mut bytes = [0u8; BUF_CAP];
    let mut fields = [field(FIELD_SENSITIVE << 2), field(0)];
    let input = fields_in(&mut bytes, fields.as_mut_ptr(), FIELDS_CAP);
    let f = check(slot::FIELDS, Outcome::Ready, &input, &fields_out(1)).unwrap_err();
    assert_eq!(f.rule, Rule::UnknownCode);
    assert_eq!(f.field, "fields.unknown_flags");
}

#[test]
fn fields_red_a_wasted_recall() {
    let mut bytes = [0u8; BUF_CAP];
    let mut fields = [field(0), field(0)];
    let input = fields_in(&mut bytes, fields.as_mut_ptr(), FIELDS_CAP);
    let mut out = fields_out(0);
    out.needed_bytes = BUF_CAP as u64;
    let f = check(slot::FIELDS, Outcome::Failed, &input, &out).unwrap_err();
    assert_eq!(f.rule, Rule::WastedRecall);
    assert_eq!(f.field, "fields");
}

#[test]
fn fields_red_count_over_cap_builds_no_slice() {
    let mut bytes = [0u8; BUF_CAP];
    let input = fields_in(
        &mut bytes,
        NonNull::<FieldSpan>::dangling().as_ptr(),
        FIELDS_CAP,
    );
    let f = check(
        slot::FIELDS,
        Outcome::Ready,
        &input,
        &fields_out(FIELDS_CAP + 1),
    )
    .unwrap_err();
    assert_eq!(f.rule, Rule::OverCap);
    assert_eq!(f.field, "fields.fields");
}

#[test]
fn fields_red_a_foreign_in() {
    let mut bytes = [0u8; BUF_CAP];
    let mut fields = [field(0), field(0)];
    let input = fields_in(&mut bytes, fields.as_mut_ptr(), FIELDS_CAP);
    let out = fields_out(0);
    let a = answer(
        slot::FIELDS,
        Outcome::Ready,
        &input,
        size_of::<FieldsIn>() - 1,
        &out,
    );
    assert_eq!(rule(Auth::check(&a)), Rule::Foreign);
}

// ---- begin_login (plugin-owned URL and form: no host cap, so no over-cap case) ----

#[test]
fn begin_login_green_an_authorize_url() {
    let out = begin_login_out(BEGIN_AUTHORIZE, "https://idp.example/authorize");
    assert_eq!(
        check(slot::BEGIN_LOGIN, Outcome::Ready, &begin_login_in(), &out),
        Ok(())
    );
}

#[test]
fn begin_login_red_two_shapes() {
    let out = begin_login_out(BEGIN_AUTHORIZE | BEGIN_FORM, "https://idp.example/");
    let f = check(slot::BEGIN_LOGIN, Outcome::Ready, &begin_login_in(), &out).unwrap_err();
    assert_eq!(f.rule, Rule::NotExactlyOne);
    assert_eq!(f.field, "begin_login.not_exactly_one");
}

#[test]
fn begin_login_red_a_named_shape_missing() {
    let out = begin_login_out(BEGIN_FORM, "");
    let f = check(slot::BEGIN_LOGIN, Outcome::Ready, &begin_login_in(), &out).unwrap_err();
    assert_eq!(f.rule, Rule::Missing);
    assert_eq!(f.field, "begin_login.missing");
}

#[test]
fn begin_login_red_a_foreign_in() {
    let input = begin_login_in();
    let out = begin_login_out(BEGIN_AUTHORIZE, "https://idp.example/authorize");
    let a = answer(
        slot::BEGIN_LOGIN,
        Outcome::Ready,
        &input,
        size_of::<BeginLoginIn>() - 1,
        &out,
    );
    assert_eq!(rule(Auth::check(&a)), Rule::Foreign);
}

// ---- unchecked ops ----

#[test]
fn open_outbound_states_no_rule_of_its_own() {
    let input = OpenOutboundIn {
        head: in_head(),
        style: NO_STR,
        credential: NO_BLOB,
        settings: NO_BLOB,
    };
    let out = OpenOutboundOut {
        head: out_head(),
        handle: 7,
    };
    assert_eq!(
        check(slot::OPEN_OUTBOUND, Outcome::Ready, &input, &out),
        Ok(())
    );
}

// ---- short ----

#[test]
fn short_is_a_failed_answer_asking_for_more() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = verify_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let mut out = identified(0, 0);
    out.needed_bytes = BUF_CAP as u64 + 1;
    for s in [slot::VERIFY, slot::COMPLETE_LOGIN] {
        let a = answer(s, Outcome::Failed, &input, size_of::<VerifyIn>(), &out);
        if s == slot::VERIFY {
            assert_eq!(Auth::check(&a), Ok(()));
        }
        assert!(Auth::short(&a));
    }
    let real = identified(0, 0);
    let a = answer(
        slot::VERIFY,
        Outcome::Failed,
        &input,
        size_of::<VerifyIn>(),
        &real,
    );
    assert!(!Auth::short(&a));
    // A strip array too small is a short answer too.
    let strip_short = IdentifyOut {
        needed_strip: 1,
        ..identified(0, 0)
    };
    let a = answer(
        slot::VERIFY,
        Outcome::Failed,
        &input,
        size_of::<VerifyIn>(),
        &strip_short,
    );
    assert_eq!(Auth::check(&a), Ok(()));
    assert!(Auth::short(&a));

    let mut fbytes = [0u8; BUF_CAP];
    let mut fields = [field(0), field(0)];
    let finput = fields_in(&mut fbytes, fields.as_mut_ptr(), FIELDS_CAP);
    let mut fout = fields_out(0);
    fout.needed_fields = FIELDS_CAP + 1;
    let a = answer(
        slot::FIELDS,
        Outcome::Failed,
        &finput,
        size_of::<FieldsIn>(),
        &fout,
    );
    assert_eq!(Auth::check(&a), Ok(()));
    assert!(Auth::short(&a));
    let a = answer(
        slot::FIELDS,
        Outcome::Ready,
        &finput,
        size_of::<FieldsIn>(),
        &fields_out(0),
    );
    assert!(!Auth::short(&a));
}

/// THE TAIL'S LOGIN RULE: the login classification is `NONE` exactly when `CAP_LOGIN` is absent,
/// and one the host knows; a tail where the two disagree refuses the load. The agreeing tails read
/// back their login kind.
#[test]
fn a_tail_whose_login_kind_disagrees_with_its_login_capability_refuses() {
    use busbar_contract::abi::auth::{
        AuthTail, CAP_INBOUND, CAP_LOGIN, LOGIN_KIND_CREDENTIAL, LOGIN_KIND_NONE,
        LOGIN_KIND_REDIRECT,
    };
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::sdk::door::statement;
    let bind = |caps: u32, login_kind: u32| {
        let tail = Box::leak(Box::new(AuthTail {
            head: KindTailHead {
                size: size_of::<AuthTail>() as u32,
                _reserved: 0,
            },
            caps,
            facts: 0,
            login_kind,
            inbound_points: if caps & CAP_INBOUND != 0 {
                POINT_HEAD
            } else {
                0
            },
            styles: std::ptr::null(),
            styles_len: 0,
            operator_principal: busbar_contract::abi::sdk::door::abi_str(""),
            credential_kinds: std::ptr::null(),
            credential_kinds_len: 0,
        }));
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            ..statement("t", "1", 0)
        };
        <Auth as Kind>::context(&st).map(|c| {
            c.and_then(|c| c.downcast::<crate::dispatch::kinds::auth::AuthFacts>().ok())
                .map(|f| f.login_kind)
        })
    };
    assert_eq!(
        bind(CAP_INBOUND, LOGIN_KIND_NONE),
        Ok(Some(LOGIN_KIND_NONE))
    );
    assert_eq!(
        bind(CAP_LOGIN, LOGIN_KIND_REDIRECT),
        Ok(Some(LOGIN_KIND_REDIRECT))
    );
    assert_eq!(
        bind(CAP_LOGIN, LOGIN_KIND_CREDENTIAL),
        Ok(Some(LOGIN_KIND_CREDENTIAL))
    );
    assert!(
        bind(CAP_LOGIN, LOGIN_KIND_NONE).is_err(),
        "login without a kind"
    );
    assert!(
        bind(CAP_INBOUND, LOGIN_KIND_REDIRECT).is_err(),
        "a kind without login"
    );
    assert!(bind(CAP_LOGIN, 9).is_err(), "an unknown kind");
}

/// THE TAIL'S POINT RULES (THE DESIGN, "Auth points and guest lists"): an inbound plugin states
/// a valid, non-empty inbound point set and no other plugin states one; every style states known
/// flags and a valid, non-empty point set. Each broken tail refuses the load; the agreeing tails read
/// back their inbound points.
#[test]
fn a_tail_with_a_broken_point_set_refuses() {
    use busbar_contract::abi::auth::{
        AuthPoints, AuthTail, StyleDecl, CAP_INBOUND, CAP_OUTBOUND, LOGIN_KIND_NONE, POINT_FRAME,
        POINT_HEAD_BODY, POINT_PEER, STYLE_NEEDS_HEADERS,
    };
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    let bind = |caps: u32, inbound_points: u32, styles: &'static [StyleDecl]| {
        let tail = Box::leak(Box::new(AuthTail {
            head: KindTailHead {
                size: size_of::<AuthTail>() as u32,
                _reserved: 0,
            },
            caps,
            facts: 0,
            login_kind: LOGIN_KIND_NONE,
            inbound_points,
            styles: styles.as_ptr(),
            styles_len: styles.len(),
            operator_principal: abi_str(""),
            credential_kinds: std::ptr::null(),
            credential_kinds_len: 0,
        }));
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            ..statement("t", "1", 0)
        };
        <Auth as Kind>::context(&st).map(|c| {
            c.and_then(|c| c.downcast::<crate::dispatch::kinds::auth::AuthFacts>().ok())
                .map(|f| f.inbound_points)
        })
    };
    let style = |flags: u32, points: u32| -> &'static [StyleDecl] {
        Box::leak(Box::new([StyleDecl {
            name: abi_str("s"),
            flags,
            points,
        }]))
    };
    assert_eq!(
        bind(CAP_INBOUND, POINT_HEAD_BODY, &[]),
        Ok(Some(AuthPoints::HEAD_BODY))
    );
    assert_eq!(
        bind(CAP_OUTBOUND, 0, style(STYLE_NEEDS_HEADERS, POINT_HEAD)),
        Ok(Some(AuthPoints::EMPTY))
    );
    // RED: the inbound set.
    assert!(
        bind(CAP_INBOUND, 0, &[]).is_err(),
        "an inbound plugin with no point"
    );
    assert!(
        bind(CAP_INBOUND, POINT_FRAME, &[]).is_err(),
        "the reserved point"
    );
    assert!(
        bind(CAP_INBOUND, POINT_HEAD | POINT_HEAD_BODY, &[]).is_err(),
        "head with head-body"
    );
    assert!(
        bind(CAP_OUTBOUND, POINT_PEER, &[]).is_err(),
        "points without verify"
    );
    // RED: a style's set and flags.
    assert!(
        bind(CAP_OUTBOUND, 0, style(0, 0)).is_err(),
        "a style with no point"
    );
    assert!(
        bind(CAP_OUTBOUND, 0, style(0, POINT_FRAME)).is_err(),
        "a style needing the reserved point"
    );
    assert!(
        bind(CAP_OUTBOUND, 0, style(1, POINT_HEAD)).is_err(),
        "the retired body-hash flag"
    );
}

/// THE CARRIERS ARE STATEMENT MARKS (the design's One Statement: an auth plugin's inbound carriers
/// are its Statement's `MARK_WORD_CARRIER` word marks, never a tail fact): the kind reads them off
/// the Statement at bind, lower-case and in order, and skips every other word class. More than the
/// host's bound refuses the load.
#[test]
fn the_carriers_are_the_statements_carrier_marks() {
    use busbar_contract::abi::auth::{AuthTail, CAP_INBOUND, LOGIN_KIND_NONE, POINT_HEAD};
    use busbar_contract::abi::mechanism::door::{KindTailHead, MarkWord, MARK_WORD_HOOK};
    use busbar_contract::abi::sdk::auth_door::carrier;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    const TAIL: AuthTail = AuthTail {
        head: KindTailHead {
            size: size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: CAP_INBOUND,
        facts: 0,
        login_kind: LOGIN_KIND_NONE,
        inbound_points: POINT_HEAD,
        styles: std::ptr::null(),
        styles_len: 0,
        operator_principal: abi_str(""),
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };
    let tail: &'static AuthTail = Box::leak(Box::new(TAIL));
    let carriers = |words: &'static [MarkWord]| {
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            mark_words: words.as_ptr(),
            mark_words_len: words.len(),
            ..statement("t", "1", 0)
        };
        <Auth as Kind>::context(&st).map(|c| {
            c.and_then(|c| c.downcast::<crate::dispatch::kinds::auth::AuthFacts>().ok())
                .map(|f| f.carriers)
        })
    };
    let hook = MarkWord {
        class: MARK_WORD_HOOK,
        _reserved: 0,
        word: abi_str("not-a-carrier"),
    };
    let words: &'static [MarkWord] =
        Box::leak(Box::new([carrier("X-Signature"), hook, carrier("x-id")]));
    assert_eq!(
        carriers(words),
        Ok(Some(vec!["x-signature".to_string(), "x-id".to_string()]))
    );
    assert_eq!(carriers(&[]), Ok(Some(Vec::new())));
    let many: &'static [MarkWord] = Box::leak(vec![carrier("x-many"); 65].into_boxed_slice());
    assert!(
        carriers(many).is_err(),
        "more carriers than the host's bound"
    );
}

/// THE OPERATOR FACT and THE KIND TAIL GROWTH RULE on the auth tail. `FACT_OPERATOR` needs
/// `CAP_INBOUND` and a non-empty principal, and a principal needs the fact; each half alone refuses
/// the load, and the agreeing tail reads its principal back. A tail of the FROZEN size (40 bytes,
/// built before `operator_principal` was appended) still loads, its appended bytes never read: the
/// principal reads absent even when the memory past its size holds one. A tail below the frozen
/// size refuses. RED: the strict "smaller than this host's" rule refused the 40-byte tail.
#[test]
fn the_operator_fact_states_its_principal_and_a_frozen_tail_still_loads() {
    use busbar_contract::abi::auth::{
        AuthTail, AUTH_TAIL_FROZEN, CAP_INBOUND, CAP_OUTBOUND, FACT_OPERATOR, LOGIN_KIND_NONE,
    };
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    let bind = |size: usize, caps: u32, facts: u32, principal: &'static str| {
        let tail = Box::leak(Box::new(AuthTail {
            head: KindTailHead {
                size: size as u32,
                _reserved: 0,
            },
            caps,
            facts,
            login_kind: LOGIN_KIND_NONE,
            inbound_points: if caps & CAP_INBOUND != 0 {
                POINT_HEAD
            } else {
                0
            },
            styles: std::ptr::null(),
            styles_len: 0,
            operator_principal: abi_str(principal),
            credential_kinds: std::ptr::null(),
            credential_kinds_len: 0,
        }));
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            ..statement("t", "1", 0)
        };
        <Auth as Kind>::context(&st).map(|c| {
            c.and_then(|c| c.downcast::<crate::dispatch::kinds::auth::AuthFacts>().ok())
                .map(|f| f.operator_principal)
        })
    };
    let host = size_of::<AuthTail>();
    assert_eq!(
        bind(host, CAP_INBOUND, FACT_OPERATOR, "admin"),
        Ok(Some(Some("admin".to_string())))
    );
    assert_eq!(bind(host, CAP_INBOUND, 0, ""), Ok(Some(None)));
    assert!(
        bind(host, CAP_INBOUND, FACT_OPERATOR, "").is_err(),
        "the fact without a principal"
    );
    assert!(
        bind(host, CAP_INBOUND, 0, "admin").is_err(),
        "a principal without the fact"
    );
    assert!(
        bind(host, CAP_OUTBOUND, FACT_OPERATOR, "admin").is_err(),
        "the operator fact on a plugin that does not verify"
    );
    assert_eq!(
        bind(AUTH_TAIL_FROZEN, CAP_INBOUND, 0, "admin"),
        Ok(Some(None)),
        "a frozen-size tail loads; its appended principal is never read"
    );
    assert!(
        bind(AUTH_TAIL_FROZEN - 8, CAP_INBOUND, 0, "").is_err(),
        "below the frozen size"
    );
}

/// THE CREDENTIAL-READ FACT (ARCHITECT 2026-10-01, AUTH-DOOR Q2 ruling B): `FACT_READS_CREDENTIALS`
/// needs `CAP_INBOUND` and a non-empty list of non-empty kinds, and a list needs the fact; each half
/// alone refuses the load, and the agreeing tail reads its kinds back, onto the instance the host
/// serves `records.secret` to. An OLDER tail (56 bytes, before the list was appended) reads none,
/// even when the memory past its size holds a list. RED: before the fact, no tail named a kind.
#[test]
fn the_credential_read_fact_states_its_kinds_and_an_old_tail_reads_none() {
    use busbar_contract::abi::auth::{
        AuthTail, CAP_INBOUND, CAP_OUTBOUND, FACT_READS_CREDENTIALS, LOGIN_KIND_NONE,
    };
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    let bind = |size: usize, caps: u32, facts: u32, kinds: &'static [AbiStr]| {
        let tail = Box::leak(Box::new(AuthTail {
            head: KindTailHead {
                size: size as u32,
                _reserved: 0,
            },
            caps,
            facts,
            login_kind: LOGIN_KIND_NONE,
            inbound_points: if caps & CAP_INBOUND != 0 {
                POINT_HEAD
            } else {
                0
            },
            styles: std::ptr::null(),
            styles_len: 0,
            operator_principal: abi_str(""),
            credential_kinds: kinds.as_ptr(),
            credential_kinds_len: kinds.len(),
        }));
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            ..statement("t", "1", 0)
        };
        <Auth as Kind>::context(&st).map(|c| <Auth as Kind>::credential_kinds(c.as_deref()))
    };
    const SIGV4: &[AbiStr] = &[abi_str("sigv4")];
    const BLANK: &[AbiStr] = &[abi_str("")];
    let host = size_of::<AuthTail>();
    let reads = FACT_READS_CREDENTIALS;
    assert_eq!(
        bind(host, CAP_INBOUND, reads, SIGV4),
        Ok(vec!["sigv4".to_string()])
    );
    assert_eq!(bind(host, CAP_INBOUND, 0, &[]), Ok(vec![]));
    assert!(
        bind(host, CAP_INBOUND, reads, &[]).is_err(),
        "the fact without kinds"
    );
    assert!(
        bind(host, CAP_INBOUND, 0, SIGV4).is_err(),
        "kinds without the fact"
    );
    assert!(
        bind(host, CAP_INBOUND, reads, BLANK).is_err(),
        "a blank kind"
    );
    assert!(
        bind(host, CAP_OUTBOUND, reads, SIGV4).is_err(),
        "a reader that does not verify"
    );
    assert_eq!(
        bind(host - 16, CAP_INBOUND, 0, SIGV4),
        Ok(vec![]),
        "a 56-byte tail reads no kinds; its appended list is never read"
    );
}
