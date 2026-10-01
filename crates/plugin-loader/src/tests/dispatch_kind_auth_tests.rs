// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth kind's `Kind` adapter over crafted answers: for each checked op a legal answer, a
//! broken rule, a reported count one above the host's cap over a dangling array (FAULT before any
//! slice exists), and an `in` smaller than the op's struct; then the short-buffer reading.

use std::mem::size_of;
use std::ptr::NonNull;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldSpan, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, IdentityOut, OpenOutboundIn, OpenOutboundOut, RequestFacts, VerifyIn,
    BEGIN_AUTHORIZE, BEGIN_FORM, FIELD_SENSITIVE, LOGIN_IDENTITY, MODE_OWN, SPAN_ABSENT,
    VERDICT_IDENTITY, VERDICT_PASS,
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
        body_hash: [0; 32],
        body_hash_present: 0,
        _reserved: 0,
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
    VerifyIn {
        head: in_head(),
        credential: NO_BLOB,
        carrier: std::ptr::null(),
        carrier_len: 0,
        request: facts(),
        out_buf,
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
        },
    }
}

fn fields_in(bytes: &mut [u8; BUF_CAP], fields: *mut FieldSpan, fields_cap: u32) -> FieldsIn {
    FieldsIn {
        head: in_head(),
        handle: 1,
        mode: MODE_OWN,
        _reserved: 0,
        request: facts(),
        caller_credential: NO_BLOB,
        field_buf: bytes.as_mut_ptr(),
        field_buf_cap: BUF_CAP,
        fields,
        fields_cap,
        _reserved2: 0,
        headers: std::ptr::null(),
        headers_len: 0,
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
            &identified(VERDICT_IDENTITY, 1)
        ),
        Ok(())
    );
    assert_eq!(
        check(
            slot::VERIFY,
            Outcome::Ready,
            &input,
            &identified(VERDICT_PASS, 0)
        ),
        Ok(())
    );
}

#[test]
fn verify_red_a_span_past_the_buffer() {
    let mut bytes = [0u8; BUF_CAP];
    let mut groups = [ABSENT; 2];
    let input = verify_in(identity_buf(&mut bytes, groups.as_mut_ptr(), GROUPS_CAP));
    let mut out = identified(VERDICT_IDENTITY, 0);
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
    let out = identified(VERDICT_IDENTITY, GROUPS_CAP + 1);
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
    let mut fields = [field(FIELD_SENSITIVE << 1), field(0)];
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
