// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields` SLOT, both credential modes, over the trampoline the door
//! macro builds — no mint, no wire, no waiting ticket: a sigv4 binding signs synchronously.

use super::*;
use crate::style;
use crate::Fields;
use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, MODE_OWN, MODE_PASSTHROUGH};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::Slot;
use std::ffi::c_void;

fn auth_span() -> busbar_contract::abi::mechanism::call::Span {
    busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 }
}

const SETTINGS: &str =
    r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#;

fn fields(s: &SigV4, handle: u64, mode: u32, caller: &str) -> (Outcome, bool) {
    let mut buf = [0_u8; 1024];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 8];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.handle = handle;
    i.mode = mode;
    i.request.authority = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: "runtime.signer.example".as_ptr(),
        len: "runtime.signer.example".len(),
    };
    i.request.canonical_path = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: "/model/m/converse".as_ptr(),
        len: "/model/m/converse".len(),
    };
    i.request.timestamp = 1_440_938_160;
    i.caller_credential = if caller.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        }
    } else {
        Blob {
            ptr: caller.as_ptr(),
            len: caller.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    };
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 8);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(s).cast_mut().cast::<c_void>();
    let outcome = Fields::call(inst, &i, &mut out);
    (outcome, out.fields_len > 0)
}

fn open(s: &SigV4, cred: Option<&str>) -> u64 {
    let binding = style::open_binding(
        style::SIGV4,
        cred.map(str::as_bytes),
        Some(SETTINGS.as_bytes()),
        &mut Vec::new(),
    )
    .expect("the binding opens");
    s.keep(binding)
}

#[test]
fn own_mode_signs_with_the_operator_credential_and_passthrough_with_the_callers() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Ready, true));
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true),
        "the caller's own credential signs, independent of the operator's binding"
    );
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Ready, false),
        "no caller credential: nothing to sign with, no fields"
    );
}

#[test]
fn a_keyless_binding_signs_nothing_in_own_mode_but_still_serves_passthrough() {
    let s = SigV4::new(1);
    let handle = open(&s, None);
    assert_eq!(
        fields(&s, handle, MODE_OWN, ""),
        (Outcome::Ready, false),
        "no operator credential: no header, not a fault"
    );
    assert_eq!(
        fields(&s, handle, MODE_PASSTHROUGH, "AKIDCALLER:CALLERSECRET"),
        (Outcome::Ready, true)
    );
}

#[test]
fn retire_drops_the_generations_handles() {
    let s = SigV4::new(1);
    let handle = open(&s, Some("AKIDEXAMPLE:SECRET"));
    s.retire(1);
    assert_eq!(fields(&s, handle, MODE_OWN, ""), (Outcome::Refused, false));
}

#[test]
fn tick_prederives_every_live_bindings_day_key_and_answers_zero_when_none_are_open() {
    let s = SigV4::new(1);
    assert_eq!(s.tick(1_000), 0, "no binding open: nothing to pre-derive");
    open(&s, Some("AKIDEXAMPLE:SECRET"));
    assert!(s.tick(1_000) > 1_000);
}
